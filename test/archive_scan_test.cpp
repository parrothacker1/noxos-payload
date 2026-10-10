#include "../archive_scan.h"

#include <zlib.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<uint8_t>;

void Append(Bytes& v, const std::string& s) { v.insert(v.end(), s.begin(), s.end()); }

void PutLe(Bytes& v, uint64_t x, int n) {
    for (int i = 0; i < n; i++) v.push_back((x >> (8 * i)) & 0xFF);
}

Bytes Gzip(const Bytes& in, int level = 6) {
    z_stream zs = {};
    deflateInit2(&zs, level, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    Bytes out(deflateBound(&zs, in.size()) + 64);
    zs.next_in = const_cast<Bytef*>(in.data());
    zs.avail_in = (uInt)in.size();
    zs.next_out = out.data();
    zs.avail_out = (uInt)out.size();
    deflate(&zs, Z_FINISH);
    out.resize(zs.total_out);
    deflateEnd(&zs);
    return out;
}

void PutOctal(Bytes& blk, size_t off, size_t len, uint64_t v) {
    std::string s;
    for (size_t i = 0; i < len - 1; i++) {
        s.insert(s.begin(), (char)('0' + (v & 7)));
        v >>= 3;
    }
    memcpy(&blk[off], s.data(), s.size());
    blk[off + len - 1] = 0;
}

Bytes TarHeader(const std::string& name, uint64_t size, char type = '0', const std::string& link = "",
                bool ustar = true) {
    Bytes blk(512, 0);
    memcpy(&blk[0], name.data(), std::min<size_t>(name.size(), 100));
    PutOctal(blk, 100, 8, 0644);
    PutOctal(blk, 124, 12, size);
    PutOctal(blk, 136, 12, 0);
    blk[156] = (uint8_t)type;
    memcpy(&blk[157], link.data(), std::min<size_t>(link.size(), 100));
    if (ustar) memcpy(&blk[257], "ustar\0" "00", 8);
    memset(&blk[148], ' ', 8);
    uint32_t sum = 0;
    for (uint8_t c : blk) sum += c;
    std::string cs;
    for (int i = 0; i < 6; i++) {
        cs.insert(cs.begin(), (char)('0' + (sum & 7)));
        sum >>= 3;
    }
    memcpy(&blk[148], cs.data(), 6);
    blk[154] = 0;
    blk[155] = ' ';
    return blk;
}

Bytes Tar(const std::vector<std::pair<std::string, std::string>>& files, bool terminate = true) {
    Bytes t;
    for (const auto& f : files) {
        Bytes h = TarHeader(f.first, f.second.size());
        t.insert(t.end(), h.begin(), h.end());
        Append(t, f.second);
        t.resize((t.size() + 511) / 512 * 512, 0);
    }
    if (terminate) t.resize(t.size() + 1024, 0);
    return t;
}

Bytes SevenZ(const Bytes& next_header, bool bad_start_crc = false, uint64_t off_override = 0,
             bool use_override = false) {
    Bytes b = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4};
    Bytes start;
    PutLe(start, use_override ? off_override : 0, 8);
    PutLe(start, next_header.size(), 8);
    PutLe(start, crc32(0L, next_header.data(), (uInt)next_header.size()), 4);
    uint32_t scrc = (uint32_t)crc32(0L, start.data(), 20);
    PutLe(b, bad_start_crc ? scrc ^ 1 : scrc, 4);
    b.insert(b.end(), start.begin(), start.end());
    b.insert(b.end(), next_header.begin(), next_header.end());
    return b;
}

Bytes Rar4Block(uint8_t type, uint16_t flags, const Bytes& body) {
    Bytes covered;
    covered.push_back(type);
    PutLe(covered, flags, 2);
    PutLe(covered, 7 + body.size(), 2);
    covered.insert(covered.end(), body.begin(), body.end());
    Bytes b;
    PutLe(b, crc32(0L, covered.data(), (uInt)covered.size()) & 0xFFFF, 2);
    b.insert(b.end(), covered.begin(), covered.end());
    return b;
}

Bytes Rar4(const std::string& name, uint16_t file_flags = 0x8000, uint16_t main_flags = 0,
           bool end = true) {
    Bytes b = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x00};
    Bytes main_body(6, 0);
    Bytes mb = Rar4Block(0x73, main_flags, main_body);
    b.insert(b.end(), mb.begin(), mb.end());
    Bytes body;
    PutLe(body, 0, 4);
    PutLe(body, 0, 4);
    body.push_back(3);
    PutLe(body, 0, 4);
    PutLe(body, 0, 4);
    body.push_back(29);
    body.push_back(0x30);
    PutLe(body, name.size(), 2);
    PutLe(body, 0, 4);
    Append(body, name);
    Bytes fb = Rar4Block(0x74, file_flags, body);
    b.insert(b.end(), fb.begin(), fb.end());
    if (end) {
        Bytes eb = Rar4Block(0x7B, 0x4000, Bytes());
        b.insert(b.end(), eb.begin(), eb.end());
    }
    return b;
}

Bytes Vint(uint64_t v) {
    Bytes b;
    do {
        uint8_t c = v & 0x7F;
        v >>= 7;
        if (v) c |= 0x80;
        b.push_back(c);
    } while (v);
    return b;
}

Bytes Rar5Block(uint64_t type, uint64_t flags, const Bytes& body, const Bytes& extra = Bytes()) {
    Bytes header = Vint(type);
    Bytes fl = Vint(flags | (extra.empty() ? 0 : 1));
    header.insert(header.end(), fl.begin(), fl.end());
    if (!extra.empty()) {
        Bytes es = Vint(extra.size());
        header.insert(header.end(), es.begin(), es.end());
    }
    header.insert(header.end(), body.begin(), body.end());
    header.insert(header.end(), extra.begin(), extra.end());
    Bytes sized = Vint(header.size());
    sized.insert(sized.end(), header.begin(), header.end());
    Bytes b;
    PutLe(b, crc32(0L, sized.data(), (uInt)sized.size()), 4);
    b.insert(b.end(), sized.begin(), sized.end());
    return b;
}

Bytes Rar5(const std::string& name, bool file_encrypted = false, bool end = true) {
    Bytes b = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00};
    Bytes m = Rar5Block(1, 0, Vint(0));
    b.insert(b.end(), m.begin(), m.end());
    Bytes body;
    for (uint64_t v : {0ull, 0ull, 0ull}) {
        Bytes x = Vint(v);
        body.insert(body.end(), x.begin(), x.end());
    }
    for (uint64_t v : {0ull, 0ull}) {
        Bytes x = Vint(v);
        body.insert(body.end(), x.begin(), x.end());
    }
    Bytes nl = Vint(name.size());
    body.insert(body.end(), nl.begin(), nl.end());
    Append(body, name);
    Bytes extra;
    if (file_encrypted) {
        Bytes rec = Vint(1);
        rec.insert(rec.end(), 4, 0);
        Bytes sz = Vint(rec.size());
        extra.insert(extra.end(), sz.begin(), sz.end());
        extra.insert(extra.end(), rec.begin(), rec.end());
    }
    Bytes f = Rar5Block(2, 0, body, extra);
    b.insert(b.end(), f.begin(), f.end());
    if (end) {
        Bytes e = Rar5Block(5, 0, Vint(0));
        b.insert(b.end(), e.begin(), e.end());
    }
    return b;
}

noxos::CheapFilterResult Scan(const Bytes& b, const std::string& type, std::string* json = nullptr) {
    std::string j;
    auto r = noxos::ScanArchive(b, type, j);
    if (json) *json = j;
    return r;
}

bool Has(const noxos::CheapFilterResult& r, const char* needle) {
    if (!r.flagged || r.reason.find(needle) == std::string::npos) {
        fprintf(stderr, "expected \"%s\", got flagged=%d \"%s\"\n", needle, r.flagged, r.reason.c_str());
        return false;
    }
    return true;
}

}  // namespace

int main() {
    {
        std::string j;
        Bytes t = Tar({{"a.txt", "hello"}, {"dir/b.txt", std::string(1000, 'x')}});
        auto r = Scan(t, "tar", &j);
        if (r.flagged) fprintf(stderr, "%s\n", r.reason.c_str());
        assert(!r.flagged);
        assert(noxos::LooksLikeTar(t.data(), t.size()));
        assert(j == "{\"file_type\":\"tar\",\"tar_entries\":2,\"tar_total_declared\":1005,"
                    "\"tar_terminated\":true,\"tar_flag_count\":0}");
        Bytes v7;
        Bytes h = TarHeader("old.txt", 3, '0', "", false);
        v7.insert(v7.end(), h.begin(), h.end());
        assert(noxos::LooksLikeTar(v7.data(), v7.size()));
        Bytes not_tar(512, 'A');
        assert(!noxos::LooksLikeTar(not_tar.data(), not_tar.size()));
    }
    {
        Bytes t;
        Bytes h = TarHeader("sparse.bin", 512, 'S');
        h[482] = 1;
        memset(&h[148], ' ', 8);
        uint32_t sum = 0;
        for (uint8_t c : h) sum += c;
        char cs[8];
        snprintf(cs, sizeof(cs), "%06o", sum);
        memcpy(&h[148], cs, 6);
        h[154] = 0;
        t.insert(t.end(), h.begin(), h.end());
        Bytes ext(512, 0);
        ext[504] = 0;
        t.insert(t.end(), ext.begin(), ext.end());
        t.resize(t.size() + 512, 'd');
        Bytes h2 = TarHeader("after.txt", 3);
        t.insert(t.end(), h2.begin(), h2.end());
        Append(t, "abc");
        t.resize((t.size() + 511) / 512 * 512, 0);
        t.resize(t.size() + 1024, 0);
        std::string j;
        auto r = Scan(t, "tar", &j);
        if (r.flagged) fprintf(stderr, "%s\n", r.reason.c_str());
        assert(!r.flagged);
        assert(j.find("\"tar_entries\":2") != std::string::npos);
    }
    assert(Has(Scan(Tar({{"../../etc/passwd", "x"}}), "tar"), "escapes the extraction directory"));
    assert(Has(Scan(Tar({{"/etc/cron.d/x", "x"}}), "tar"), "escapes the extraction directory"));
    assert(!Scan(Tar({{"a/..b/c", "x"}}), "tar").flagged);
    {
        Bytes t;
        Bytes h = TarHeader("link", 0, '2', "../../../etc/shadow");
        t.insert(t.end(), h.begin(), h.end());
        t.resize(t.size() + 1024, 0);
        assert(Has(Scan(t, "tar"), "symlink"));
        t.clear();
        h = TarHeader("link", 0, '2', "target.txt");
        t.insert(t.end(), h.begin(), h.end());
        t.resize(t.size() + 1024, 0);
        assert(!Scan(t, "tar").flagged);
    }
    {
        Bytes t = Tar({{"a.txt", "hello"}});
        t[10] ^= 0x20;
        assert(Has(Scan(t, "tar"), "checksum mismatch"));
        t = Tar({{"a.txt", "hello"}});
        Bytes h = TarHeader("big.bin", 100000);
        std::copy(h.begin(), h.end(), t.begin());
        assert(Has(Scan(t, "tar"), "declares 100000 bytes but the archive ends first"));
        t = Tar({{"a.txt", "hello"}});
        Append(t, "\x7F" "ELF payload");
        assert(Has(Scan(t, "tar"), "embedded ELF executable signature after the tar end"));
        t = Tar({{"a.txt", "hello"}});
        t.resize(t.size() + 10240, 0);
        assert(!Scan(t, "tar").flagged);
        t = Tar({{"a.txt", "hello"}});
        t.insert(t.end(), 5000, 'z');
        assert(Has(Scan(t, "tar"), "5000 bytes of data after the tar end"));
        t = Tar({{"a.txt", "hello"}}, false);
        std::string j;
        assert(!Scan(t, "tar", &j).flagged);
        assert(j.find("\"tar_terminated\":false") != std::string::npos);
        t = Tar({{"a.txt", "hello"}});
        Append(t, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        assert(Has(Scan(t, "tar"), "EICAR"));
    }

    {
        std::string j;
        Bytes in(5000);
        for (size_t i = 0; i < in.size(); i++) in[i] = (uint8_t)(i % 251);
        auto r = Scan(Gzip(in), "gzip", &j);
        assert(!r.flagged);
        assert(j.find("\"gzip_members\":1") != std::string::npos);
        assert(j.find("\"gzip_output_bytes\":5000") != std::string::npos);
        assert(j.find("\"gzip_complete\":true") != std::string::npos);

        Bytes gz = Gzip(in);
        Bytes two = gz;
        two.insert(two.end(), gz.begin(), gz.end());
        assert(!Scan(two, "gzip", &j).flagged);
        assert(j.find("\"gzip_members\":2") != std::string::npos);

        Bytes cut(gz.begin(), gz.end() - 20);
        assert(Has(Scan(cut, "gzip"), "truncated"));
        Bytes bad = gz;
        bad[bad.size() - 6] ^= 0xFF;
        assert(Has(Scan(bad, "gzip"), "corrupt"));
        Bytes mid = gz;
        mid[mid.size() / 2] ^= 0xFF;
        assert(Scan(mid, "gzip").flagged);

        Bytes z = gz;
        z.insert(z.end(), 3000, 0);
        assert(!Scan(z, "gzip").flagged);
        z = gz;
        Append(z, "PK\x03\x04 smuggled");
        assert(Has(Scan(z, "gzip"), "embedded ZIP local file header signature after the gzip data"));
        z = gz;
        z.insert(z.end(), 5000, 'q');
        assert(Has(Scan(z, "gzip"), "5000 bytes of data after the gzip data"));
        z = gz;
        z[3] |= 0x80;
        assert(Has(Scan(z, "gzip"), "reserved flag bits"));

        Bytes zeros(30 * 1024 * 1024, 0);
        assert(Has(Scan(Gzip(zeros, 9), "gzip"), "decompression bomb"));

        Bytes elf = {0x7F, 'E', 'L', 'F'};
        elf.resize(2000, 7);
        assert(!Scan(Gzip(elf), "gzip", &j).flagged);
        assert(j.find("\"gzip_inner\":\"elf\"") != std::string::npos);

        Bytes tar = Tar({{"a.txt", "hello"}});
        Scan(Gzip(tar), "gzip", &j);
        assert(j.find("\"gzip_inner\":\"tar\"") != std::string::npos);
        assert(!Scan(Gzip(tar), "gzip").flagged);
        assert(Has(Scan(Gzip(Tar({{"../x", "y"}})), "gzip"), "escapes the extraction directory"));
    }

    {
        Bytes hdr = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        std::string j;
        auto r = Scan(SevenZ(hdr), "7z", &j);
        if (r.flagged) fprintf(stderr, "%s\n", r.reason.c_str());
        assert(!r.flagged);
        assert(j == "{\"file_type\":\"7z\",\"sevenz_next_header_size\":10,\"sevenz_encrypted\":false,"
                    "\"sevenz_flag_count\":0}");
        assert(Has(Scan(SevenZ(hdr, true), "7z"), "start header CRC mismatch"));
        assert(Has(Scan(SevenZ(hdr, false, 1000, true), "7z"), "lies outside the file"));
        Bytes b = SevenZ(hdr);
        b[b.size() - 3] ^= 0xFF;
        assert(Has(Scan(b, "7z"), "next header CRC mismatch"));
        b = SevenZ(hdr);
        Append(b, "PK\x03\x04 hidden");
        assert(Has(Scan(b, "7z"), "bytes of data after the 7z archive (contains ZIP local file header"));
        Bytes aes = {0x17, 0x06, 0xF1, 0x07, 0x01, 0x00};
        assert(Has(Scan(SevenZ(aes), "7z"), "AES encryption"));
        b = SevenZ(hdr);
        b[6] = 9;
        assert(Scan(b, "7z").flagged);
        assert(Has(Scan(Bytes{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}, "7z"), "shorter than"));
        assert(!Scan(SevenZ(Bytes()), "7z").flagged);
    }

    {
        std::string j;
        auto r = Scan(Rar4("docs/a.txt"), "rar", &j);
        if (r.flagged) fprintf(stderr, "%s\n", r.reason.c_str());
        assert(!r.flagged);
        assert(j == "{\"file_type\":\"rar\",\"rar_version\":4,\"rar_entries\":1,\"rar_encrypted\":false,"
                    "\"rar_flag_count\":0}");
        assert(Has(Scan(Rar4("../../evil.sh"), "rar"), "escapes the extraction directory"));
        assert(Has(Scan(Rar4("a.txt", 0x8004), "rar"), "password-protected files"));
        assert(Has(Scan(Rar4("a.txt", 0x8000, 0x0080), "rar"), "headers are encrypted"));
        assert(Has(Scan(Rar4("a.txt", 0x8000, 0, false), "rar"), "no end-of-archive block"));
        Bytes b = Rar4("a.txt");
        Append(b, "MZ trailing executable");
        assert(Has(Scan(b, "rar"), "embedded Windows PE/DOS executable signature after the RAR end"));
        b = Rar4("a.txt");
        b.insert(b.end(), 5000, 'x');
        assert(Has(Scan(b, "rar"), "5000 bytes of data after the RAR end"));
        b = Rar4("a.txt");
        b[7 + 2] ^= 0x01;
        assert(Has(Scan(b, "rar"), "CRC mismatch"));
        b = Rar4("a.txt");
        b.resize(b.size() - 3);
        assert(Scan(b, "rar").flagged);
    }

    {
        std::string j;
        auto r = Scan(Rar5("docs/a.txt"), "rar", &j);
        if (r.flagged) fprintf(stderr, "%s\n", r.reason.c_str());
        assert(!r.flagged);
        assert(j == "{\"file_type\":\"rar\",\"rar_version\":5,\"rar_entries\":1,\"rar_encrypted\":false,"
                    "\"rar_flag_count\":0}");
        assert(Has(Scan(Rar5("../x"), "rar"), "escapes the extraction directory"));
        assert(Has(Scan(Rar5("a.txt", true), "rar"), "password-protected files"));
        assert(Has(Scan(Rar5("a.txt", false, false), "rar"), "no end-of-archive block"));
        Bytes b = Rar5("a.txt");
        Append(b, "%PDF-1.4 hidden");
        assert(Has(Scan(b, "rar"), "embedded PDF signature after the RAR end"));
        b = Rar5("a.txt");
        b[8 + 5] ^= 0x01;
        assert(Has(Scan(b, "rar"), "CRC mismatch"));
        Bytes enc = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00};
        Bytes eb = Rar5Block(4, 0, Vint(0));
        enc.insert(enc.end(), eb.begin(), eb.end());
        assert(Has(Scan(enc, "rar"), "headers are encrypted"));
        assert(Has(Scan(Bytes{'R', 'a', 'r', '!', 0x1A, 0x07, 0x09}, "rar"), "unknown version"));
    }

    printf("ok: archive_scan_test passed\n");
    return 0;
}
