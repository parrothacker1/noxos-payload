#include "zip_scan.h"

#include <zlib.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <set>

#include "json_util.h"
#include "scan_util.h"

namespace noxos {
namespace {

constexpr uint32_t kEocdSig = 0x06054b50;
constexpr uint32_t kCdSig = 0x02014b50;
constexpr uint32_t kLocalSig = 0x04034b50;
constexpr size_t kEocdLen = 22;
constexpr size_t kCdLen = 46;
constexpr size_t kLocalLen = 30;
constexpr size_t kMaxEocdComment = 0xFFFF;

constexpr uint64_t kBombMinEntryBytes = 10ull * 1024 * 1024;
constexpr uint64_t kBombRatio = 200;
constexpr uint64_t kBombTotalBytes = 1ull * 1024 * 1024 * 1024;

constexpr size_t kMagicProbeBytes = 16;
constexpr size_t kMaxManifestBytes = 1024 * 1024;
constexpr size_t kMaxCertBytes = 64 * 1024;
constexpr size_t kDexHeaderLen = 0x70;
constexpr size_t kDexSampleBytes = 1024 * 1024;
constexpr size_t kMinEntropySampleBytes = 4096;
constexpr double kPackedDexEntropy = 7.2;
constexpr size_t kMaxAxmlStrings = 100000;
constexpr size_t kMaxReportedPermissions = 2000;
constexpr size_t kMaxReportedPermissionLen = 256;
constexpr size_t kMaxRelsBytes = 1024 * 1024;
constexpr size_t kMaxRelsFiles = 256;

const char* const kDangerousExternalRelTypes[] = {
    "attachedTemplate", "oleObject", "frame", "subDocument",
};

constexpr uint32_t kApkSigV2 = 0x7109871a;
constexpr uint32_t kApkSigV3 = 0xf05368c0;
constexpr uint32_t kApkSigV31 = 0x1b93ad61;
const char kApkSigMagic[] = "APK Sig Block 42";
const char kDebugCertCn[] = "Android Debug";

const char* const kHighRiskPermissions[] = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.CALL_PHONE",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
};
constexpr size_t kHighRiskFlagCount = 4;

const char* const kDataExtensions[] = {
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "txt", "xml", "json",
    "html", "htm", "css", "mp3", "ogg", "wav", "mp4", "ttf", "otf", "properties",
};

struct Entry {
    std::string name;
    bool encrypted = false;
    uint16_t method;
    uint32_t comp;
    uint32_t uncomp;
    size_t local_off;
    size_t data_off;
    size_t data_end;
};

struct Meta {
    bool is_apk = false;
    bool is_ooxml = false;
    size_t entries = 0;
    const char* signing = "none";
    size_t permission_strings = 0;
    size_t high_risk_permissions = 0;
    std::vector<std::string> permissions;
    bool ooxml_macros = false;
    size_t ooxml_activex = 0;
    size_t ooxml_embeddings = 0;
    size_t ooxml_external_rels = 0;
    size_t encrypted_entries = 0;
    uint64_t uncompressed_total = 0;
    std::string dex_version;
    double dex_entropy = -1.0;
};

struct Flags {
    std::string first;
    size_t count = 0;
    void Add(std::string reason) {
        if (count++ == 0) first = std::move(reason);
    }
};

bool InflatePrefix(const uint8_t* src, size_t src_len, uint16_t method, size_t max_out,
                   std::vector<uint8_t>& out) {
    out.clear();
    if (method == 0) {
        out.assign(src, src + std::min(src_len, max_out));
        return true;
    }
    if (method != 8 || max_out == 0) return false;

    out.resize(max_out);
    z_stream zs = {};
    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) return false;
    zs.next_in = const_cast<Bytef*>(src);
    zs.avail_in = (uInt)std::min(src_len, (size_t)UINT32_MAX);
    zs.next_out = out.data();
    zs.avail_out = (uInt)max_out;
    int rc = inflate(&zs, Z_SYNC_FLUSH);
    size_t produced = max_out - zs.avail_out;
    inflateEnd(&zs);
    out.resize(produced);
    return rc == Z_STREAM_END || ((rc == Z_OK || rc == Z_BUF_ERROR) && produced > 0);
}

bool IsPrintableAscii(const std::string& s) {
    for (char c : s) {
        if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E) return false;
    }
    return true;
}

bool IsPathTraversal(const std::string& name) {
    if (name.empty()) return false;
    if (name[0] == '/' || name[0] == '\\') return true;
    if (name.size() >= 2 && name[1] == ':') return true;
    if (name.find('\0') != std::string::npos) return true;
    size_t start = 0;
    while (start <= name.size()) {
        size_t end = name.find_first_of("/\\", start);
        if (end == std::string::npos) end = name.size();
        if (name.compare(start, end - start, "..") == 0 && end - start == 2) return true;
        start = end + 1;
    }
    return false;
}

std::string LowerExtension(const std::string& name) {
    size_t slash = name.find_last_of("/\\");
    size_t dot = name.find_last_of('.');
    if (dot == std::string::npos || (slash != std::string::npos && dot < slash)) return "";
    std::string ext = name.substr(dot + 1);
    for (char& c : ext) c = (char)tolower((unsigned char)c);
    return ext;
}

bool IsDataExtension(const std::string& ext) {
    for (const char* e : kDataExtensions) {
        if (ext == e) return true;
    }
    return false;
}

const char* ExecutableMagic(const std::vector<uint8_t>& p) {
    if (p.size() >= 4 && memcmp(p.data(), "\x7F""ELF", 4) == 0) return "ELF";
    if (p.size() >= 4 && memcmp(p.data(), "dex\n", 4) == 0) return "DEX";
    if (p.size() >= 2 && p[0] == 'M' && p[1] == 'Z') return "PE";
    return nullptr;
}

bool ParseAxmlStrings(const std::vector<uint8_t>& x, std::vector<std::string>& out) {
    if (x.size() < 8 || ReadU16Le(x.data()) != 0x0003) return false;
    size_t sp = ReadU16Le(x.data() + 2);
    if (sp < 8 || sp + 28 > x.size()) return false;
    if (ReadU16Le(x.data() + sp) != 0x0001) return false;
    size_t hdr = ReadU16Le(x.data() + sp + 2);
    size_t csize = ReadU32Le(x.data() + sp + 4);
    uint32_t count = ReadU32Le(x.data() + sp + 8);
    bool utf8 = (ReadU32Le(x.data() + sp + 16) & (1u << 8)) != 0;
    size_t strings_start = ReadU32Le(x.data() + sp + 20);
    if (hdr < 28 || csize > x.size() - sp || hdr > csize) return false;
    if (count > kMaxAxmlStrings || (size_t)count * 4 > csize - hdr) return false;
    if (strings_start > csize) return false;

    size_t chunk_end = sp + csize;
    size_t base = sp + strings_start;
    for (uint32_t i = 0; i < count; i++) {
        size_t off = ReadU32Le(x.data() + sp + hdr + (size_t)i * 4);
        if (off >= chunk_end - base) return false;
        size_t pos = base + off;
        std::string s;
        if (utf8) {
            if (pos + 2 > chunk_end) return false;
            pos += (x[pos] & 0x80) ? 2 : 1;
            if (pos + 2 > chunk_end) return false;
            size_t len = x[pos];
            if (len & 0x80) {
                len = ((len & 0x7F) << 8) | x[pos + 1];
                pos += 2;
            } else {
                pos += 1;
            }
            if (len > chunk_end - pos) return false;
            s.assign(reinterpret_cast<const char*>(x.data() + pos), len);
        } else {
            if (pos + 2 > chunk_end) return false;
            size_t len = ReadU16Le(x.data() + pos);
            pos += 2;
            if (len & 0x8000) {
                if (pos + 2 > chunk_end) return false;
                len = ((len & 0x7FFF) << 16) | ReadU16Le(x.data() + pos);
                pos += 2;
            }
            if (len > (chunk_end - pos) / 2) return false;
            s.resize(len);
            for (size_t k = 0; k < len; k++) {
                uint16_t ch = ReadU16Le(x.data() + pos + k * 2);
                s[k] = ch < 0x80 ? (char)ch : '?';
            }
        }
        out.push_back(std::move(s));
    }
    return true;
}

std::string XmlAttr(const std::string& tag, const char* attr) {
    std::string key = std::string(" ") + attr + "=";
    size_t k = tag.find(key);
    if (k == std::string::npos) return "";
    size_t q = k + key.size();
    if (q >= tag.size() || (tag[q] != '"' && tag[q] != '\'')) return "";
    size_t end = tag.find(tag[q], q + 1);
    if (end == std::string::npos) return "";
    return tag.substr(q + 1, end - q - 1);
}

std::string CheckRels(const std::vector<uint8_t>& xml, Meta& meta) {
    std::string s(xml.begin(), xml.end());
    std::string reason;
    size_t pos = 0;
    while ((pos = s.find("<Relationship ", pos)) != std::string::npos) {
        size_t end = s.find('>', pos);
        if (end == std::string::npos) break;
        std::string tag = s.substr(pos, end - pos);
        pos = end;
        if (XmlAttr(tag, "TargetMode") != "External") continue;
        meta.ooxml_external_rels++;
        std::string type = XmlAttr(tag, "Type");
        std::string kind = type.substr(type.find_last_of('/') + 1);
        for (const char* bad : kDangerousExternalRelTypes) {
            if (kind == bad && reason.empty()) {
                reason = "Office document loads an external " + kind + " from \"" +
                         XmlAttr(tag, "Target").substr(0, 200) + "\"";
            }
        }
    }
    return reason;
}

std::string CheckOoxml(const std::vector<uint8_t>& b, const std::vector<Entry>& entries, Meta& meta) {
    std::vector<uint8_t> buf;
    size_t rels_seen = 0;
    std::string reason;
    for (const auto& e : entries) {
        std::string lower = e.name;
        for (char& ch : lower) ch = (char)tolower((unsigned char)ch);
        std::string ext = LowerExtension(e.name);
        if (lower.size() >= 14 && lower.compare(lower.size() - 14, 14, "vbaproject.bin") == 0) {
            meta.ooxml_macros = true;
        }
        if (lower.find("/activex/") != std::string::npos && ext == "bin") meta.ooxml_activex++;
        if (lower.find("/embeddings/") != std::string::npos) meta.ooxml_embeddings++;
        if (ext != "rels" || rels_seen >= kMaxRelsFiles || e.uncomp > kMaxRelsBytes) continue;
        rels_seen++;
        if (!InflatePrefix(b.data() + e.data_off, e.comp, e.method, e.uncomp, buf)) continue;
        std::string r = CheckRels(buf, meta);
        if (reason.empty()) reason = r;
    }
    if (meta.ooxml_macros) return "Office document contains VBA macros (vbaProject.bin)";
    if (meta.ooxml_activex > 0) return "Office document contains ActiveX controls";
    return reason;
}

void CheckDex(const std::vector<uint8_t>& b, const Entry& e, Meta& meta, Flags& flags) {
    std::vector<uint8_t> dex;
    if (!InflatePrefix(b.data() + e.data_off, e.comp, e.method,
                       std::min<size_t>(e.uncomp, kDexHeaderLen + kDexSampleBytes), dex)) {
        flags.Add("classes.dex could not be decompressed");
        return;
    }
    if (dex.size() < kDexHeaderLen) {
        flags.Add("classes.dex is shorter than a DEX header");
        return;
    }
    const uint8_t* h = dex.data();
    if (memcmp(h, "dex\n", 4) != 0 || h[7] != 0 || !isdigit(h[4]) || !isdigit(h[5]) ||
        !isdigit(h[6])) {
        flags.Add("classes.dex has no valid DEX magic");
    } else {
        meta.dex_version.assign(reinterpret_cast<const char*>(h + 4), 3);
    }
    if (ReadU32Le(h + 0x28) != 0x12345678) flags.Add("classes.dex has a non-standard endian tag");
    if (ReadU32Le(h + 0x24) != kDexHeaderLen) flags.Add("classes.dex header_size is not 0x70");
    uint32_t file_size = ReadU32Le(h + 0x20);
    if (file_size != e.uncomp) {
        flags.Add("classes.dex header declares " + std::to_string(file_size) +
                  " bytes but the entry is " + std::to_string(e.uncomp));
    }
    uint32_t map_off = ReadU32Le(h + 0x34);
    if (map_off == 0 || map_off >= file_size) flags.Add("classes.dex map_off is out of bounds");
    uint64_t data_end = (uint64_t)ReadU32Le(h + 0x6C) + ReadU32Le(h + 0x68);
    if (data_end > file_size) flags.Add("classes.dex data section runs past end of file");

    if (const char* sig = FindKnownBadSignature(dex.data(), dex.size())) {
        flags.Add(std::string("classes.dex contains ") + sig);
    }
    size_t body = dex.size() - kDexHeaderLen;
    if (body >= kMinEntropySampleBytes) {
        meta.dex_entropy = ShannonEntropy(dex.data() + kDexHeaderLen, body);
        if (meta.dex_entropy > kPackedDexEntropy) {
            char buf[96];
            snprintf(buf, sizeof(buf),
                     "classes.dex entropy %.2f bits/byte suggests packed or encrypted code",
                     meta.dex_entropy);
            flags.Add(buf);
        }
    }
}

size_t FindEocd(const std::vector<uint8_t>& b) {
    if (b.size() < kEocdLen) return SIZE_MAX;
    size_t lowest = b.size() > kEocdLen + kMaxEocdComment ? b.size() - kEocdLen - kMaxEocdComment : 0;
    for (size_t i = b.size() - kEocdLen + 1; i-- > lowest;) {
        if (ReadU32Le(b.data() + i) == kEocdSig) return i;
    }
    return SIZE_MAX;
}

void ScanZipImpl(const std::vector<uint8_t>& b, Meta& meta, Flags& flags) {
    const size_t size = b.size();
    if (const char* sig = FindKnownBadSignature(b.data(), size)) {
        flags.Add(std::string("contains ") + sig);
    }
    if (size < kEocdLen) {
        flags.Add("ZIP too small to hold an end-of-central-directory record");
        return;
    }

    size_t eocd = FindEocd(b);
    if (eocd == SIZE_MAX) {
        flags.Add("no ZIP end-of-central-directory record found");
        return;
    }

    size_t comment_len = ReadU16Le(b.data() + eocd + 20);
    size_t eocd_end = eocd + kEocdLen + comment_len;
    if (eocd_end > size) {
        flags.Add("ZIP end record comment runs past end of file");
        return;
    }
    if (eocd_end < size) {
        flags.Add(std::to_string(size - eocd_end) + " bytes of appended data after ZIP end record");
    }

    size_t total = ReadU16Le(b.data() + eocd + 10);
    size_t cd_size = ReadU32Le(b.data() + eocd + 12);
    size_t cd_off = ReadU32Le(b.data() + eocd + 16);
    if (total == 0xFFFF || cd_off == 0xFFFFFFFF) return;
    if (cd_off > eocd || cd_size > eocd - cd_off) {
        flags.Add("ZIP central directory lies outside the file");
        return;
    }
    if (cd_off + cd_size != eocd) flags.Add("unexplained data between ZIP central directory and end record");

    size_t archive_end = cd_off;
    size_t sig_block = SIZE_MAX;
    if (cd_off >= 24 && memcmp(b.data() + cd_off - 16, kApkSigMagic, 16) == 0) {
        uint64_t block_size = ReadU64Le(b.data() + cd_off - 24);
        if (block_size < 24 || block_size > cd_off - 8 ||
            ReadU64Le(b.data() + cd_off - block_size - 8) != block_size) {
            flags.Add("malformed APK Signing Block");
        } else {
            sig_block = cd_off - (size_t)block_size - 8;
            archive_end = sig_block;
        }
    }

    std::vector<Entry> entries;
    std::set<std::string> names;
    bool total_bomb = false;
    bool cd_broken = false;
    size_t p = cd_off;
    for (size_t i = 0; i < total; i++) {
        if (p + kCdLen > eocd || ReadU32Le(b.data() + p) != kCdSig) {
            flags.Add("ZIP central directory entry " + std::to_string(i) + " is malformed");
            cd_broken = true;
            break;
        }
        Entry e;
        uint16_t gp_flags = ReadU16Le(b.data() + p + 8);
        e.method = ReadU16Le(b.data() + p + 10);
        e.comp = ReadU32Le(b.data() + p + 20);
        e.uncomp = ReadU32Le(b.data() + p + 24);
        size_t name_len = ReadU16Le(b.data() + p + 28);
        size_t var_len = name_len + ReadU16Le(b.data() + p + 30) + ReadU16Le(b.data() + p + 32);
        e.local_off = ReadU32Le(b.data() + p + 42);
        if (var_len > eocd - p - kCdLen) {
            flags.Add("ZIP central directory entry runs past its end");
            cd_broken = true;
            break;
        }
        e.name.assign(reinterpret_cast<const char*>(b.data() + p + kCdLen), name_len);
        p += kCdLen + var_len;

        if (IsPathTraversal(e.name)) flags.Add("path traversal in ZIP entry name \"" + e.name + "\"");
        if (gp_flags & 0x0001) {
            e.encrypted = true;
            meta.encrypted_entries++;
            flags.Add("ZIP entry \"" + e.name + "\" is encrypted; its contents cannot be inspected");
        }
        if (!names.insert(e.name).second) flags.Add("duplicate ZIP entry name \"" + e.name + "\"");
        meta.uncompressed_total += e.uncomp;
        if (e.uncomp >= kBombMinEntryBytes && e.uncomp > kBombRatio * (uint64_t)e.comp) {
            flags.Add("ZIP entry \"" + e.name + "\" expands " +
                      std::to_string(e.uncomp / std::max<uint32_t>(e.comp, 1)) + "x (zip bomb)");
        }
        if (!total_bomb && meta.uncompressed_total > kBombTotalBytes) {
            total_bomb = true;
            flags.Add("ZIP declares over 1 GiB of uncompressed data (zip bomb)");
        }

        if (e.local_off > archive_end || archive_end - e.local_off < kLocalLen ||
            ReadU32Le(b.data() + e.local_off) != kLocalSig) {
            flags.Add("ZIP entry \"" + e.name + "\" has no valid local header");
            continue;
        }
        size_t lname = ReadU16Le(b.data() + e.local_off + 26);
        size_t lvar = lname + ReadU16Le(b.data() + e.local_off + 28);
        if (lvar > archive_end - e.local_off - kLocalLen) {
            flags.Add("ZIP entry \"" + e.name + "\" local header runs past archive data");
            continue;
        }
        if (lname != name_len ||
            memcmp(b.data() + e.local_off + kLocalLen, e.name.data(), name_len) != 0) {
            flags.Add("ZIP entry \"" + e.name + "\" local and central names differ");
        }
        e.data_off = e.local_off + kLocalLen + lvar;
        if (e.comp > archive_end - e.data_off) {
            flags.Add("ZIP entry \"" + e.name + "\" data runs past archive data");
            continue;
        }
        e.data_end = e.data_off + e.comp;
        entries.push_back(std::move(e));
    }
    if (!cd_broken && p != eocd) flags.Add("ZIP central directory size does not match its entries");
    meta.entries = entries.size();

    std::vector<const Entry*> by_off;
    for (const auto& e : entries) by_off.push_back(&e);
    std::sort(by_off.begin(), by_off.end(),
              [](const Entry* a, const Entry* c) { return a->local_off < c->local_off; });
    if (!by_off.empty() && by_off[0]->local_off > 0 &&
        (by_off[0]->local_off < 4 || ReadU32Le(b.data()) != kLocalSig)) {
        flags.Add(std::to_string(by_off[0]->local_off) + " bytes of data before the first ZIP entry");
    }
    for (size_t i = 1; i < by_off.size(); i++) {
        if (by_off[i - 1]->data_end > by_off[i]->local_off) {
            flags.Add("ZIP entries \"" + by_off[i - 1]->name + "\" and \"" + by_off[i]->name +
                      "\" overlap");
            break;
        }
    }

    const Entry* manifest = nullptr;
    const Entry* dex = nullptr;
    const Entry* v1_cert = nullptr;
    std::vector<uint8_t> buf;
    for (const auto& e : entries) {
        if (e.name == "AndroidManifest.xml") manifest = &e;
        if (e.name == "[Content_Types].xml") meta.is_ooxml = true;
        if (e.name == "classes.dex") dex = &e;
        std::string ext = LowerExtension(e.name);
        if (e.name.rfind("META-INF/", 0) == 0 && (ext == "rsa" || ext == "dsa" || ext == "ec")) {
            v1_cert = &e;
        }
        if (e.encrypted || !IsDataExtension(ext)) continue;
        if (!InflatePrefix(b.data() + e.data_off, e.comp, e.method, kMagicProbeBytes, buf)) continue;
        if (const char* kind = ExecutableMagic(buf)) {
            flags.Add("ZIP entry \"" + e.name + "\" is named ." + ext + " but contains " + kind +
                      " code");
        }
    }

    if (!manifest) {
        if (meta.is_ooxml) {
            std::string r = CheckOoxml(b, entries, meta);
            if (!r.empty()) flags.Add(r);
        }
        return;
    }
    meta.is_apk = true;
    meta.is_ooxml = false;

    bool debug_signed = false;
    if (sig_block != SIZE_MAX) {
        size_t pos = sig_block + 8;
        size_t pairs_end = cd_off - 24;
        bool has_v3 = false;
        bool has_v2 = false;
        while (pos + 12 <= pairs_end) {
            uint64_t len = ReadU64Le(b.data() + pos);
            if (len < 4 || len > pairs_end - pos - 8) {
                flags.Add("malformed APK Signing Block entry");
                break;
            }
            uint32_t id = ReadU32Le(b.data() + pos + 8);
            if (id == kApkSigV2) has_v2 = true;
            if (id == kApkSigV3 || id == kApkSigV31) has_v3 = true;
            pos += 8 + (size_t)len;
        }
        meta.signing = has_v3 ? "v3" : has_v2 ? "v2" : v1_cert ? "v1" : "none";
        debug_signed = ContainsBytes(b.data() + sig_block, cd_off - sig_block, kDebugCertCn,
                                     sizeof(kDebugCertCn) - 1);
    } else if (v1_cert) {
        meta.signing = "v1";
        if (!v1_cert->encrypted &&
            InflatePrefix(b.data() + v1_cert->data_off, v1_cert->comp, v1_cert->method,
                          std::min<size_t>(v1_cert->uncomp, kMaxCertBytes), buf)) {
            debug_signed = ContainsBytes(buf.data(), buf.size(), kDebugCertCn,
                                         sizeof(kDebugCertCn) - 1);
        }
    }

    if (!manifest->encrypted && manifest->uncomp <= kMaxManifestBytes) {
        std::vector<std::string> strings;
        if (!InflatePrefix(b.data() + manifest->data_off, manifest->comp, manifest->method,
                           manifest->uncomp, buf) ||
            buf.size() != manifest->uncomp) {
            flags.Add("AndroidManifest.xml could not be decompressed");
        } else if (!ParseAxmlStrings(buf, strings)) {
            flags.Add("AndroidManifest.xml is not valid binary XML");
        } else {
            bool sms = false;
            bool accessibility = false;
            std::set<std::string> seen;
            for (const auto& s : strings) {
                if (s.find(".permission.") == std::string::npos || !seen.insert(s).second) continue;
                meta.permission_strings++;
                if (meta.permissions.size() < kMaxReportedPermissions &&
                    s.size() <= kMaxReportedPermissionLen && IsPrintableAscii(s)) {
                    meta.permissions.push_back(s);
                }
                for (const char* perm : kHighRiskPermissions) {
                    if (s != perm) continue;
                    meta.high_risk_permissions++;
                    if (s.find("_SMS") != std::string::npos) sms = true;
                    if (s.find("ACCESSIBILITY") != std::string::npos) accessibility = true;
                }
            }
            if (sms && accessibility) {
                flags.Add("APK requests both SMS and accessibility-service permissions");
            }
            if (meta.high_risk_permissions >= kHighRiskFlagCount) {
                flags.Add("APK requests " + std::to_string(meta.high_risk_permissions) +
                          " high-risk permissions");
            }
        }
    }

    if (dex && !dex->encrypted) CheckDex(b, *dex, meta, flags);

    if (strcmp(meta.signing, "none") == 0) flags.Add("APK is unsigned");
    if (debug_signed) flags.Add("APK is signed with the Android debug certificate");
}

}  // namespace

bool LooksLikeZip(const std::vector<uint8_t>& file_bytes) {
    return (file_bytes.size() >= 4 && ReadU32Le(file_bytes.data()) == kLocalSig) ||
           FindEocd(file_bytes) != SIZE_MAX;
}

CheapFilterResult ScanZip(const std::vector<uint8_t>& file_bytes, std::string& out_json,
                          std::string* out_type) {
    Meta meta;
    Flags flags;
    ScanZipImpl(file_bytes, meta, flags);
    CheapFilterResult result;
    result.flagged = flags.count > 0;
    result.reason = flags.first;

    const char* type = meta.is_apk ? "apk" : meta.is_ooxml ? "ooxml" : "zip";
    if (out_type) *out_type = type;
    out_json = std::string("{\"file_type\":\"") + type +
               "\",\"zip_entries\":" + std::to_string(meta.entries) +
               ",\"zip_encrypted_entries\":" + std::to_string(meta.encrypted_entries) +
               ",\"zip_uncompressed_total\":" + std::to_string(meta.uncompressed_total) +
               ",\"zip_flag_count\":" + std::to_string(flags.count);
    if (meta.is_apk) {
        out_json += std::string(",\"apk_signing\":\"") + meta.signing +
                    "\",\"permission_strings\":" + std::to_string(meta.permission_strings) +
                    ",\"high_risk_permissions\":" + std::to_string(meta.high_risk_permissions);
        out_json += ",\"permissions\":[";
        for (size_t i = 0; i < meta.permissions.size(); i++) {
            if (i > 0) out_json += ",";
            out_json += "\"" + JsonEscape(meta.permissions[i]) + "\"";
        }
        out_json += "]";
        if (!meta.dex_version.empty()) out_json += ",\"dex_version\":\"" + meta.dex_version + "\"";
        if (meta.dex_entropy >= 0) {
            char buf[48];
            snprintf(buf, sizeof(buf), ",\"dex_entropy\":%.3f", meta.dex_entropy);
            out_json += buf;
        }
    }
    if (meta.is_ooxml) {
        out_json += std::string(",\"ooxml_macros\":") + (meta.ooxml_macros ? "true" : "false") +
                    ",\"ooxml_activex\":" + std::to_string(meta.ooxml_activex) +
                    ",\"ooxml_embeddings\":" + std::to_string(meta.ooxml_embeddings) +
                    ",\"ooxml_external_rels\":" + std::to_string(meta.ooxml_external_rels);
    }
    out_json += "}";
    return result;
}

}  // namespace noxos
