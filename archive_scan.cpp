#include "archive_scan.h"

#include <zlib.h>

#include <algorithm>
#include <cstring>

#include "file_type.h"
#include "scan_util.h"

namespace noxos {
namespace {

constexpr size_t kTarBlock = 512;
constexpr size_t kMaxTrailingBenign = 4096;
constexpr uint64_t kBombMinOutput = 10ull * 1024 * 1024;
constexpr uint64_t kBombRatio = 200;
constexpr uint64_t kBombTotal = 1ull * 1024 * 1024 * 1024;
constexpr size_t kGzipOutputCap = 64 * 1024 * 1024;
constexpr size_t kGzipInspectBytes = 8 * 1024 * 1024;
constexpr size_t kInflateChunk = 64 * 1024;
constexpr size_t kMaxGzipMembers = 1024;
constexpr size_t kMax7zHeaderScan = 1024 * 1024;
constexpr size_t kMaxRarBlocks = 100000;
constexpr size_t kMaxTarEntries = 1000000;
constexpr size_t kMaxSparseExtBlocks = 100000;

struct Flags {
    std::string first;
    size_t count = 0;
    void Add(std::string reason) {
        if (count++ == 0) first = std::move(reason);
    }
};

bool ParseOctal(const uint8_t* p, size_t n, uint64_t& out) {
    size_t i = 0;
    while (i < n && p[i] == ' ') i++;
    uint64_t v = 0;
    size_t digits = 0;
    while (i < n && p[i] >= '0' && p[i] <= '7') {
        if (v > (UINT64_MAX >> 3)) return false;
        v = (v << 3) | (uint64_t)(p[i] - '0');
        i++;
        digits++;
    }
    if (digits == 0) return false;
    while (i < n && (p[i] == ' ' || p[i] == 0)) i++;
    out = v;
    return i == n;
}

bool TarChecksumOk(const uint8_t* blk) {
    uint64_t stored;
    if (!ParseOctal(blk + 148, 8, stored)) return false;
    uint64_t sum = 0;
    int64_t signed_sum = 0;
    for (size_t i = 0; i < kTarBlock; i++) {
        uint8_t c = (i >= 148 && i < 156) ? ' ' : blk[i];
        sum += c;
        signed_sum += (int8_t)c;
    }
    return sum == stored || (signed_sum >= 0 && (uint64_t)signed_sum == stored);
}

bool AllZero(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i]) return false;
    }
    return true;
}

bool PathEscapes(const std::string& name) {
    if (name.empty()) return false;
    if (name[0] == '/' || name[0] == '\\') return true;
    if (name.size() >= 2 && name[1] == ':') return true;
    size_t start = 0;
    while (start <= name.size()) {
        size_t end = name.find_first_of("/\\", start);
        if (end == std::string::npos) end = name.size();
        if (end - start == 2 && name.compare(start, 2, "..") == 0) return true;
        start = end + 1;
    }
    return false;
}

std::string CString(const uint8_t* p, size_t max) {
    size_t n = 0;
    while (n < max && p[n]) n++;
    return std::string(reinterpret_cast<const char*>(p), n);
}

struct TarResult {
    size_t entries = 0;
    uint64_t total_declared = 0;
    bool terminated = false;
};

TarResult WalkTar(const uint8_t* d, size_t len, bool complete, Flags& flags) {
    TarResult r;
    size_t pos = 0;
    size_t zero_blocks = 0;
    while (len - pos >= kTarBlock && r.entries < kMaxTarEntries) {
        const uint8_t* blk = d + pos;
        if (AllZero(blk, kTarBlock)) {
            pos += kTarBlock;
            if (++zero_blocks >= 2) {
                r.terminated = true;
                break;
            }
            continue;
        }
        zero_blocks = 0;
        if (!TarChecksumOk(blk)) {
            flags.Add("tar header checksum mismatch at offset " + std::to_string(pos));
            return r;
        }
        uint64_t size = 0;
        if (blk[124] & 0x80) {
            for (size_t i = 125; i < 136; i++) {
                if (size > (UINT64_MAX >> 8)) {
                    flags.Add("tar entry size field overflows");
                    return r;
                }
                size = (size << 8) | blk[i];
            }
        } else if (!ParseOctal(blk + 124, 12, size)) {
            flags.Add("tar entry has a malformed size field at offset " + std::to_string(pos));
            return r;
        }
        uint8_t type = blk[156];
        bool is_ustar = memcmp(blk + 257, "ustar", 5) == 0;
        std::string name = CString(blk, 100);
        if (is_ustar && blk[345]) name = CString(blk + 345, 155) + "/" + name;
        bool meta_entry = type == 'L' || type == 'K' || type == 'x' || type == 'g';
        if (!meta_entry) {
            r.entries++;
            if (PathEscapes(name)) flags.Add("tar entry \"" + name.substr(0, 120) + "\" escapes the extraction directory");
            if (type == '1' || type == '2') {
                std::string link = CString(blk + 157, 100);
                if (PathEscapes(link)) {
                    flags.Add(std::string("tar ") + (type == '2' ? "symlink" : "hardlink") + " \"" +
                              name.substr(0, 80) + "\" points outside the extraction directory");
                }
                size = 0;
            }
            if (r.total_declared > UINT64_MAX - size) r.total_declared = UINT64_MAX;
            else r.total_declared += size;
            if (r.total_declared > kBombTotal) flags.Add("tar declares over 1 GiB of entry data");
        }
        size_t sparse_ext = 0;
        if (type == 'S' && blk[482]) {
            size_t q = pos;
            while (sparse_ext < kMaxSparseExtBlocks) {
                q += kTarBlock;
                if (len < q || len - q < kTarBlock) break;
                sparse_ext++;
                if (!d[q + 504]) break;
            }
        }
        uint64_t blocks = size / kTarBlock + (size % kTarBlock ? 1 : 0);
        if (len - pos < (1 + sparse_ext) * kTarBlock ||
            blocks > (len - pos - (1 + sparse_ext) * kTarBlock) / kTarBlock) {
            if (complete) {
                flags.Add("tar entry \"" + name.substr(0, 80) + "\" declares " + std::to_string(size) +
                          " bytes but the archive ends first");
            }
            return r;
        }
        pos += (1 + sparse_ext) * kTarBlock + (size_t)blocks * kTarBlock;
    }
    if (complete && r.terminated) {
        size_t tail = pos;
        while (tail < len && d[tail] == 0) tail++;
        if (tail < len) {
            std::vector<uint8_t> rest(d + tail, d + len);
            if (const char* m = FindForeignMagic(rest, 0)) {
                flags.Add(std::string("embedded ") + m + " signature after the tar end-of-archive marker");
            } else if (len - tail > kMaxTrailingBenign) {
                flags.Add(std::to_string(len - tail) + " bytes of data after the tar end-of-archive marker");
            }
        }
    }
    return r;
}

CheapFilterResult ScanTar(const std::vector<uint8_t>& b, std::string& out_json) {
    Flags flags;
    if (const char* sig = FindKnownBadSignature(b.data(), b.size())) {
        flags.Add(std::string("contains ") + sig);
    }
    TarResult t = WalkTar(b.data(), b.size(), true, flags);
    out_json = "{\"file_type\":\"tar\",\"tar_entries\":" + std::to_string(t.entries) +
               ",\"tar_total_declared\":" + std::to_string(t.total_declared) +
               ",\"tar_terminated\":" + (t.terminated ? "true" : "false") +
               ",\"tar_flag_count\":" + std::to_string(flags.count) + "}";
    CheapFilterResult r;
    r.flagged = flags.count > 0;
    r.reason = flags.first;
    return r;
}

CheapFilterResult ScanGzip(const std::vector<uint8_t>& b, std::string& out_json) {
    Flags flags;
    if (b.size() >= 10 && (b[3] & 0xE0)) flags.Add("gzip header sets reserved flag bits");

    z_stream zs = {};
    bool ok = inflateInit2(&zs, 16 + MAX_WBITS) == Z_OK;
    std::vector<uint8_t> chunk(kInflateChunk);
    std::vector<uint8_t> inspect;
    uint64_t out_total = 0;
    size_t members = 0;
    bool complete = false;
    bool capped = false;
    size_t in_pos = 0;

    if (ok) {
        zs.next_in = const_cast<Bytef*>(b.data());
        zs.avail_in = (uInt)std::min<size_t>(b.size(), UINT32_MAX);
        while (true) {
            zs.next_out = chunk.data();
            zs.avail_out = (uInt)chunk.size();
            int rc = inflate(&zs, Z_NO_FLUSH);
            size_t produced = chunk.size() - zs.avail_out;
            if (produced) {
                if (inspect.size() < kGzipInspectBytes) {
                    size_t take = std::min(produced, kGzipInspectBytes - inspect.size());
                    inspect.insert(inspect.end(), chunk.begin(), chunk.begin() + take);
                }
                out_total += produced;
            }
            in_pos = b.size() - zs.avail_in;
            if (rc == Z_STREAM_END) {
                members++;
                if (zs.avail_in >= 2 && b[in_pos] == 0x1F && b[in_pos + 1] == 0x8B && members < kMaxGzipMembers) {
                    inflateReset(&zs);
                    continue;
                }
                complete = true;
                break;
            }
            if (rc == Z_DATA_ERROR || rc == Z_MEM_ERROR || rc == Z_NEED_DICT) {
                flags.Add(std::string("gzip stream is corrupt (") + (zs.msg ? zs.msg : "inflate error") + ")");
                break;
            }
            if (rc == Z_BUF_ERROR && zs.avail_in == 0) {
                flags.Add("gzip stream is truncated");
                break;
            }
            if (out_total >= kGzipOutputCap) {
                capped = true;
                break;
            }
        }
        inflateEnd(&zs);
    } else {
        flags.Add("gzip decoder could not be initialised");
    }

    uint64_t consumed = std::max<uint64_t>(in_pos, 1);
    if (out_total >= kBombMinOutput && out_total / consumed > kBombRatio) {
        flags.Add("gzip expands " + std::to_string(out_total / consumed) + "x (decompression bomb)");
    }

    if (complete) {
        size_t tail = in_pos;
        while (tail < b.size() && b[tail] == 0) tail++;
        if (tail < b.size()) {
            if (const char* m = FindForeignMagic(b, tail)) {
                flags.Add(std::string("embedded ") + m + " signature after the gzip data");
            } else if (b.size() - tail > kMaxTrailingBenign) {
                flags.Add(std::to_string(b.size() - tail) + " bytes of data after the gzip data");
            }
        }
    }

    std::string inner = inspect.empty() ? "empty" : DetectFileType(inspect);
    TarResult tar;
    if (!inspect.empty() && LooksLikeTar(inspect.data(), inspect.size())) {
        inner = "tar";
        tar = WalkTar(inspect.data(), inspect.size(), complete && out_total <= kGzipInspectBytes, flags);
    }

    out_json = "{\"file_type\":\"gzip\",\"gzip_members\":" + std::to_string(members) +
               ",\"gzip_output_bytes\":" + std::to_string(out_total) +
               ",\"gzip_complete\":" + (complete ? "true" : "false") +
               ",\"gzip_output_capped\":" + (capped ? "true" : "false") +
               ",\"gzip_inner\":\"" + inner + "\",\"tar_entries\":" + std::to_string(tar.entries) +
               ",\"gzip_flag_count\":" + std::to_string(flags.count) + "}";
    CheapFilterResult r;
    r.flagged = flags.count > 0;
    r.reason = flags.first;
    return r;
}

CheapFilterResult Scan7z(const std::vector<uint8_t>& b, std::string& out_json) {
    Flags flags;
    bool encrypted = false;
    uint64_t next_size = 0;
    if (const char* sig = FindKnownBadSignature(b.data(), b.size())) {
        flags.Add(std::string("contains ") + sig);
    }
    if (b.size() < 32) {
        flags.Add("7z file is shorter than its 32-byte signature header");
    } else {
        if (b[6] != 0) flags.Add("7z archive has an unknown major version " + std::to_string(b[6]));
        uint32_t start_crc = ReadU32Le(b.data() + 8);
        if ((uint32_t)crc32(0L, b.data() + 12, 20) != start_crc) {
            flags.Add("7z start header CRC mismatch");
        }
        uint64_t next_off = ReadU64Le(b.data() + 12);
        next_size = ReadU64Le(b.data() + 20);
        uint32_t next_crc = ReadU32Le(b.data() + 28);
        uint64_t avail = b.size() - 32;
        if (next_off > avail || next_size > avail - next_off) {
            flags.Add("7z next header lies outside the file");
        } else {
            size_t hdr = 32 + (size_t)next_off;
            if (next_size > 0 && (uint32_t)crc32(0L, b.data() + hdr, (uInt)next_size) != next_crc) {
                flags.Add("7z next header CRC mismatch");
            }
            size_t end = hdr + (size_t)next_size;
            if (end < b.size()) {
                size_t tail = end;
                const char* m = FindForeignMagic(b, tail);
                flags.Add(std::to_string(b.size() - end) + " bytes of data after the 7z archive" +
                          (m ? std::string(" (contains ") + m + " signature)" : std::string()));
            }
            static const uint8_t kAes[] = {0x06, 0xF1, 0x07, 0x01};
            size_t scan = (size_t)std::min<uint64_t>(next_size, kMax7zHeaderScan);
            if (ContainsBytes(b.data() + hdr, scan, reinterpret_cast<const char*>(kAes), sizeof(kAes))) {
                encrypted = true;
                flags.Add("7z archive uses AES encryption; its contents cannot be inspected");
            }
        }
    }
    out_json = "{\"file_type\":\"7z\",\"sevenz_next_header_size\":" + std::to_string(next_size) +
               ",\"sevenz_encrypted\":" + (encrypted ? "true" : "false") +
               ",\"sevenz_flag_count\":" + std::to_string(flags.count) + "}";
    CheapFilterResult r;
    r.flagged = flags.count > 0;
    r.reason = flags.first;
    return r;
}

bool ReadVint(const std::vector<uint8_t>& b, size_t& pos, size_t limit, uint64_t& out) {
    out = 0;
    for (int shift = 0; shift < 70; shift += 7) {
        if (pos >= limit || pos >= b.size()) return false;
        uint8_t c = b[pos++];
        if (shift < 64) out |= (uint64_t)(c & 0x7F) << shift;
        if (!(c & 0x80)) return true;
    }
    return false;
}

struct RarResult {
    int version = 0;
    size_t entries = 0;
    bool encrypted = false;
};

RarResult WalkRar4(const std::vector<uint8_t>& b, Flags& flags) {
    RarResult r;
    r.version = 4;
    size_t pos = 7;
    bool ended = false;
    for (size_t n = 0; n < kMaxRarBlocks && b.size() - pos >= 7; n++) {
        uint16_t crc = ReadU16Le(b.data() + pos);
        uint8_t type = b[pos + 2];
        uint16_t bflags = ReadU16Le(b.data() + pos + 3);
        size_t hsize = ReadU16Le(b.data() + pos + 5);
        if (hsize < 7 || hsize > b.size() - pos) {
            flags.Add("RAR block header at offset " + std::to_string(pos) + " is malformed");
            return r;
        }
        uint64_t data_size = 0;
        if (bflags & 0x8000) {
            if (hsize < 11) {
                flags.Add("RAR block header at offset " + std::to_string(pos) + " is malformed");
                return r;
            }
            data_size = ReadU32Le(b.data() + pos + 7);
        }
        if (type == 0x73 && (bflags & 0x0080)) {
            r.encrypted = true;
            flags.Add("RAR archive headers are encrypted; its contents cannot be inspected");
            return r;
        }
        if ((uint16_t)(crc32(0L, b.data() + pos + 2, (uInt)(hsize - 2)) & 0xFFFF) != crc &&
            type != 0x74 && type != 0x7A) {
            flags.Add("RAR block header CRC mismatch at offset " + std::to_string(pos));
            return r;
        }
        if (type == 0x74) {
            r.entries++;
            if (bflags & 0x0004) {
                r.encrypted = true;
                flags.Add("RAR archive contains password-protected files; their contents cannot be inspected");
            }
            if (hsize >= 32) {
                size_t name_len = ReadU16Le(b.data() + pos + 26);
                size_t name_off = pos + 32 + ((bflags & 0x0100) ? 8 : 0);
                if (name_off <= pos + hsize && name_len <= pos + hsize - name_off) {
                    std::string name = CString(b.data() + name_off, name_len);
                    if (PathEscapes(name)) {
                        flags.Add("RAR entry \"" + name.substr(0, 120) + "\" escapes the extraction directory");
                    }
                }
            }
        }
        uint64_t next = pos + hsize + data_size;
        if (type == 0x7B) {
            ended = true;
            pos = (size_t)std::min<uint64_t>(next, b.size());
            break;
        }
        if (next > b.size()) {
            flags.Add("RAR block at offset " + std::to_string(pos) + " runs past the end of the file");
            return r;
        }
        pos = (size_t)next;
    }
    if (!ended) {
        flags.Add("RAR archive has no end-of-archive block");
    } else if (pos < b.size()) {
        const char* m = FindForeignMagic(b, pos);
        if (m) flags.Add(std::string("embedded ") + m + " signature after the RAR end-of-archive block");
        else if (b.size() - pos > kMaxTrailingBenign) {
            flags.Add(std::to_string(b.size() - pos) + " bytes of data after the RAR end-of-archive block");
        }
    }
    return r;
}

RarResult WalkRar5(const std::vector<uint8_t>& b, Flags& flags) {
    RarResult r;
    r.version = 5;
    size_t pos = 8;
    bool ended = false;
    for (size_t n = 0; n < kMaxRarBlocks && b.size() - pos >= 7; n++) {
        uint32_t crc = ReadU32Le(b.data() + pos);
        size_t p = pos + 4;
        uint64_t hsize;
        if (!ReadVint(b, p, b.size(), hsize) || hsize > b.size() - p) {
            flags.Add("RAR5 block header at offset " + std::to_string(pos) + " is malformed");
            return r;
        }
        size_t hdr_start = pos + 4;
        size_t hdr_end = p + (size_t)hsize;
        if ((uint32_t)crc32(0L, b.data() + hdr_start, (uInt)(hdr_end - hdr_start)) != crc) {
            flags.Add("RAR5 block header CRC mismatch at offset " + std::to_string(pos));
            return r;
        }
        uint64_t type, bflags, extra_size = 0, data_size = 0;
        size_t q = p;
        if (!ReadVint(b, q, hdr_end, type) || !ReadVint(b, q, hdr_end, bflags) ||
            ((bflags & 1) && !ReadVint(b, q, hdr_end, extra_size)) ||
            ((bflags & 2) && !ReadVint(b, q, hdr_end, data_size))) {
            flags.Add("RAR5 block header at offset " + std::to_string(pos) + " is malformed");
            return r;
        }
        if (type == 4) {
            r.encrypted = true;
            flags.Add("RAR archive headers are encrypted; its contents cannot be inspected");
            return r;
        }
        if (type == 2 || type == 3) {
            uint64_t file_flags, unpacked, attrs, comp, host, name_len;
            size_t f = q;
            bool ok = ReadVint(b, f, hdr_end, file_flags) && ReadVint(b, f, hdr_end, unpacked) &&
                      ReadVint(b, f, hdr_end, attrs);
            if (ok && (file_flags & 2)) f += 4;
            if (ok && (file_flags & 4)) f += 4;
            ok = ok && f <= hdr_end && ReadVint(b, f, hdr_end, comp) && ReadVint(b, f, hdr_end, host) &&
                 ReadVint(b, f, hdr_end, name_len);
            if (type == 2) r.entries++;
            if (ok && name_len <= hdr_end - f && type == 2) {
                std::string name(reinterpret_cast<const char*>(b.data() + f), (size_t)name_len);
                if (PathEscapes(name)) {
                    flags.Add("RAR entry \"" + name.substr(0, 120) + "\" escapes the extraction directory");
                }
            }
            if (extra_size > 0 && extra_size <= hdr_end - hdr_start) {
                size_t e = hdr_end - (size_t)extra_size;
                while (e < hdr_end) {
                    uint64_t rec_size, rec_type;
                    size_t rec_start = e;
                    if (!ReadVint(b, e, hdr_end, rec_size) || rec_size > hdr_end - e) break;
                    size_t rec_end = e + (size_t)rec_size;
                    if (ReadVint(b, e, rec_end, rec_type) && rec_type == 1 && type == 2) {
                        r.encrypted = true;
                        flags.Add("RAR archive contains password-protected files; their contents cannot be inspected");
                    }
                    e = rec_end > rec_start ? rec_end : hdr_end;
                }
            }
        }
        uint64_t next = (uint64_t)hdr_end + data_size;
        if (type == 5) {
            ended = true;
            pos = (size_t)std::min<uint64_t>(next, b.size());
            break;
        }
        if (next > b.size()) {
            flags.Add("RAR block at offset " + std::to_string(pos) + " runs past the end of the file");
            return r;
        }
        pos = (size_t)next;
    }
    if (!ended) {
        flags.Add("RAR archive has no end-of-archive block");
    } else if (pos < b.size()) {
        const char* m = FindForeignMagic(b, pos);
        if (m) flags.Add(std::string("embedded ") + m + " signature after the RAR end-of-archive block");
        else if (b.size() - pos > kMaxTrailingBenign) {
            flags.Add(std::to_string(b.size() - pos) + " bytes of data after the RAR end-of-archive block");
        }
    }
    return r;
}

CheapFilterResult ScanRar(const std::vector<uint8_t>& b, std::string& out_json) {
    Flags flags;
    if (const char* sig = FindKnownBadSignature(b.data(), b.size())) {
        flags.Add(std::string("contains ") + sig);
    }
    RarResult rr;
    if (b.size() >= 8 && b[6] == 1 && b[7] == 0) rr = WalkRar5(b, flags);
    else if (b.size() >= 7 && b[6] == 0) rr = WalkRar4(b, flags);
    else flags.Add("RAR signature has an unknown version byte");
    out_json = "{\"file_type\":\"rar\",\"rar_version\":" + std::to_string(rr.version) +
               ",\"rar_entries\":" + std::to_string(rr.entries) +
               ",\"rar_encrypted\":" + (rr.encrypted ? "true" : "false") +
               ",\"rar_flag_count\":" + std::to_string(flags.count) + "}";
    CheapFilterResult r;
    r.flagged = flags.count > 0;
    r.reason = flags.first;
    return r;
}

}  // namespace

bool LooksLikeTar(const uint8_t* p, size_t n) {
    if (n < kTarBlock) return false;
    if (!TarChecksumOk(p)) return false;
    if (memcmp(p + 257, "ustar", 5) == 0) return true;
    if (p[0] == 0) return false;
    for (size_t i = 0; i < 100 && p[i]; i++) {
        if (p[i] < 0x20 || p[i] > 0x7E) return false;
    }
    uint64_t size;
    return p[124] & 0x80 ? true : ParseOctal(p + 124, 12, size);
}

CheapFilterResult ScanArchive(const std::vector<uint8_t>& b, const std::string& type,
                              std::string& out_json) {
    if (type == "gzip") return ScanGzip(b, out_json);
    if (type == "tar") return ScanTar(b, out_json);
    if (type == "7z") return Scan7z(b, out_json);
    return ScanRar(b, out_json);
}

}  // namespace noxos
