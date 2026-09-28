#include "../zip_scan.h"

#include <zlib.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace {

void Put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(x & 0xFF);
    v.push_back(x >> 8);
}

void Put32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; i++) v.push_back((x >> (8 * i)) & 0xFF);
}

void Put64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; i++) v.push_back((x >> (8 * i)) & 0xFF);
}

void Set32(std::vector<uint8_t>& v, size_t at, uint32_t x) {
    for (int i = 0; i < 4; i++) v[at + i] = (x >> (8 * i)) & 0xFF;
}

std::vector<uint8_t> Bytes(const std::string& s) { return std::vector<uint8_t>(s.begin(), s.end()); }

std::vector<uint8_t> RawDeflate(const std::vector<uint8_t>& in) {
    z_stream zs = {};
    deflateInit2(&zs, 9, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    std::vector<uint8_t> out(deflateBound(&zs, in.size()));
    zs.next_in = const_cast<Bytef*>(in.data());
    zs.avail_in = in.size();
    zs.next_out = out.data();
    zs.avail_out = out.size();
    deflate(&zs, Z_FINISH);
    out.resize(zs.total_out);
    deflateEnd(&zs);
    return out;
}

struct TestEntry {
    std::string name;
    std::vector<uint8_t> data;
    bool deflate = false;
    uint32_t uncomp_override = 0;
    std::string local_name;
};

struct ZipOpts {
    std::vector<uint8_t> prefix;
    std::vector<uint8_t> sig_block;
    std::vector<uint8_t> suffix;
};

std::vector<uint8_t> BuildZip(const std::vector<TestEntry>& entries, const ZipOpts& o = {}) {
    std::vector<uint8_t> z = o.prefix;
    std::vector<uint8_t> cd;
    for (const auto& e : entries) {
        std::vector<uint8_t> body = e.deflate ? RawDeflate(e.data) : e.data;
        uint32_t uncomp = e.uncomp_override ? e.uncomp_override : (uint32_t)e.data.size();
        uint32_t off = (uint32_t)z.size();
        const std::string& lname = e.local_name.empty() ? e.name : e.local_name;
        Put32(z, 0x04034b50);
        Put16(z, 20); Put16(z, 0); Put16(z, e.deflate ? 8 : 0); Put16(z, 0); Put16(z, 0);
        Put32(z, 0); Put32(z, (uint32_t)body.size()); Put32(z, uncomp);
        Put16(z, (uint16_t)lname.size()); Put16(z, 0);
        z.insert(z.end(), lname.begin(), lname.end());
        z.insert(z.end(), body.begin(), body.end());

        Put32(cd, 0x02014b50);
        Put16(cd, 20); Put16(cd, 20); Put16(cd, 0); Put16(cd, e.deflate ? 8 : 0);
        Put16(cd, 0); Put16(cd, 0);
        Put32(cd, 0); Put32(cd, (uint32_t)body.size()); Put32(cd, uncomp);
        Put16(cd, (uint16_t)e.name.size()); Put16(cd, 0); Put16(cd, 0);
        Put16(cd, 0); Put16(cd, 0); Put32(cd, 0); Put32(cd, off);
        cd.insert(cd.end(), e.name.begin(), e.name.end());
    }
    z.insert(z.end(), o.sig_block.begin(), o.sig_block.end());
    uint32_t cd_off = (uint32_t)z.size();
    z.insert(z.end(), cd.begin(), cd.end());
    Put32(z, 0x06054b50);
    Put16(z, 0); Put16(z, 0);
    Put16(z, (uint16_t)entries.size()); Put16(z, (uint16_t)entries.size());
    Put32(z, (uint32_t)cd.size()); Put32(z, cd_off);
    Put16(z, 0);
    z.insert(z.end(), o.suffix.begin(), o.suffix.end());
    return z;
}

std::vector<uint8_t> SigBlock(uint32_t id, const std::string& value) {
    std::vector<uint8_t> pairs;
    Put64(pairs, 4 + value.size());
    Put32(pairs, id);
    pairs.insert(pairs.end(), value.begin(), value.end());
    uint64_t size = pairs.size() + 8 + 16;
    std::vector<uint8_t> b;
    Put64(b, size);
    b.insert(b.end(), pairs.begin(), pairs.end());
    Put64(b, size);
    const char magic[] = "APK Sig Block 42";
    b.insert(b.end(), magic, magic + 16);
    return b;
}

std::vector<uint8_t> Axml(const std::vector<std::string>& strings) {
    std::vector<uint8_t> offsets, data;
    for (const auto& s : strings) {
        Put32(offsets, (uint32_t)data.size());
        Put16(data, (uint16_t)s.size());
        for (char c : s) Put16(data, (uint8_t)c);
        Put16(data, 0);
    }
    while (data.size() % 4) data.push_back(0);
    std::vector<uint8_t> pool;
    Put16(pool, 0x0001); Put16(pool, 28);
    Put32(pool, (uint32_t)(28 + offsets.size() + data.size()));
    Put32(pool, (uint32_t)strings.size()); Put32(pool, 0); Put32(pool, 0);
    Put32(pool, (uint32_t)(28 + offsets.size())); Put32(pool, 0);
    pool.insert(pool.end(), offsets.begin(), offsets.end());
    pool.insert(pool.end(), data.begin(), data.end());
    std::vector<uint8_t> x;
    Put16(x, 0x0003); Put16(x, 8); Put32(x, (uint32_t)(8 + pool.size()));
    x.insert(x.end(), pool.begin(), pool.end());
    return x;
}

std::vector<uint8_t> Dex(size_t body_len, bool random_body) {
    std::vector<uint8_t> d(0x70 + body_len, 0);
    memcpy(d.data(), "dex\n035\0", 8);
    Set32(d, 0x20, (uint32_t)d.size());
    Set32(d, 0x24, 0x70);
    Set32(d, 0x28, 0x12345678);
    Set32(d, 0x34, (uint32_t)d.size() - 4);
    Set32(d, 0x68, (uint32_t)body_len);
    Set32(d, 0x6C, 0x70);
    std::mt19937 rng(42);
    for (size_t i = 0x70; i < d.size(); i++) {
        d[i] = random_body ? (uint8_t)rng() : (uint8_t)("const-string v0 "[i % 16]);
    }
    return d;
}

struct ApkOpts {
    std::vector<std::string> perms = {"android.permission.INTERNET"};
    std::vector<uint8_t> dex = Dex(8192, false);
    bool signed_v2 = true;
    std::string cert = "CN=Example Corp";
    std::vector<TestEntry> extra;
};

std::vector<uint8_t> BuildApk(const ApkOpts& a) {
    std::vector<TestEntry> es;
    es.push_back({"AndroidManifest.xml", Axml(a.perms), true});
    es.push_back({"classes.dex", a.dex, true});
    for (const auto& e : a.extra) es.push_back(e);
    ZipOpts o;
    if (a.signed_v2) o.sig_block = SigBlock(0x7109871a, a.cert);
    return BuildZip(es, o);
}

noxos::CheapFilterResult Scan(const std::vector<uint8_t>& z, std::string* json = nullptr) {
    std::string j;
    auto r = noxos::ScanZip(z, j);
    if (json) *json = j;
    return r;
}

bool Has(const noxos::CheapFilterResult& r, const char* needle) {
    if (!r.flagged || r.reason.find(needle) == std::string::npos) {
        fprintf(stderr, "expected reason containing \"%s\", got flagged=%d \"%s\"\n", needle,
                r.flagged, r.reason.c_str());
        return false;
    }
    return true;
}

}  // namespace

int main() {
    {
        auto z = BuildZip({{"readme.txt", Bytes("hello")}, {"img/a.png", Bytes("\x89PNG....")}});
        assert(noxos::LooksLikeZip(z));
        std::string j;
        auto r = Scan(z, &j);
        assert(!r.flagged);
        assert(j == "{\"file_type\":\"zip\",\"zip_entries\":2}");
    }
    assert(Has(Scan(BuildZip({{"../../etc/passwd", Bytes("x")}})), "path traversal"));
    assert(Has(Scan(BuildZip({{"a/..\\b", Bytes("x")}})), "path traversal"));
    assert(Has(Scan(BuildZip({{"/abs", Bytes("x")}})), "path traversal"));
    assert(!Scan(BuildZip({{"a/..b/c", Bytes("x")}})).flagged);
    assert(Has(Scan(BuildZip({{"a", Bytes("1")}, {"a", Bytes("2")}})), "duplicate"));
    assert(Has(Scan(BuildZip({{"a", Bytes("1"), false, 0, "b"}})), "names differ"));
    {
        ZipOpts o;
        o.suffix = Bytes("\x7F" "ELF trailing payload");
        assert(Has(Scan(BuildZip({{"a", Bytes("1")}}, o)), "appended data"));
    }
    {
        ZipOpts o;
        o.prefix = Dex(64, false);
        auto z = BuildZip({{"a", Bytes("1")}}, o);
        assert(noxos::LooksLikeZip(z));
        assert(Has(Scan(z), "before the first ZIP entry"));
    }
    {
        ZipOpts o;
        o.prefix = {'P', 'K', 3, 4};
        o.prefix.resize(132, 0);
        assert(!Scan(BuildZip({{"a", Bytes("1")}}, o)).flagged);
    }
    assert(Has(Scan(BuildZip({{"icon.png", Bytes("\x7F" "ELF\x02\x01\x01")}})), "contains ELF"));
    assert(Has(Scan(BuildZip({{"assets/x.jpg", Dex(64, false), true}})), "contains DEX"));
    assert(!Scan(BuildZip({{"lib/arm64-v8a/libx.so", Bytes("\x7F" "ELF\x02\x01\x01")}})).flagged);
    {
        std::vector<uint8_t> zeros(64 * 1024, 0);
        assert(Has(Scan(BuildZip({{"big.bin", zeros, true, 50u * 1024 * 1024}})), "zip bomb"));
    }
    {
        auto z = BuildZip({{"a", Bytes("aaaaaaaa")}, {"b", Bytes("bbbbbbbb")}});
        size_t cd = z.size() - 22 - (46 + 1) * 2;
        Set32(z, cd + 20, 30);
        Set32(z, cd + 24, 30);
        assert(Has(Scan(z), "overlap"));
    }
    assert(Has(Scan(BuildZip({{"eicar.txt",
                               Bytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")}})),
               "EICAR"));
    assert(Has(Scan(Bytes("PK\x03\x04 truncated")), "end-of-central-directory"));
    {
        auto z = BuildZip({{"a", Bytes("1")}});
        z.resize(z.size() - 5);
        std::string j;
        noxos::ScanZip(z, j);
    }

    {
        std::string j;
        auto r = Scan(BuildApk({}), &j);
        if (r.flagged) fprintf(stderr, "%s\n", r.reason.c_str());
        assert(!r.flagged);
        assert(j == "{\"file_type\":\"apk\",\"zip_entries\":2,\"apk_signing\":\"v2\","
                    "\"permission_strings\":1,\"high_risk_permissions\":0}");
    }
    {
        ApkOpts a;
        a.signed_v2 = false;
        assert(Has(Scan(BuildApk(a)), "unsigned"));
    }
    {
        ApkOpts a;
        a.signed_v2 = false;
        a.extra.push_back({"META-INF/CERT.RSA", Bytes("..CN=Android Debug, O=Android, C=US.."), true});
        std::string j;
        assert(Has(Scan(BuildApk(a), &j), "debug certificate"));
        assert(j.find("\"apk_signing\":\"v1\"") != std::string::npos);
    }
    {
        ApkOpts a;
        a.cert = "..CN=Android Debug..";
        assert(Has(Scan(BuildApk(a)), "debug certificate"));
    }
    {
        ApkOpts a;
        a.perms = {"android.permission.INTERNET", "android.permission.RECEIVE_SMS",
                   "android.permission.BIND_ACCESSIBILITY_SERVICE"};
        assert(Has(Scan(BuildApk(a)), "SMS and accessibility"));
    }
    {
        ApkOpts a;
        a.perms = {"android.permission.CALL_PHONE", "android.permission.READ_CONTACTS",
                   "android.permission.RECORD_AUDIO", "android.permission.SYSTEM_ALERT_WINDOW",
                   "android.permission.READ_CONTACTS"};
        assert(Has(Scan(BuildApk(a)), "4 high-risk"));
    }
    {
        ApkOpts a;
        a.perms = {"android.permission.CALL_PHONE", "android.permission.READ_CONTACTS",
                   "android.permission.RECORD_AUDIO"};
        assert(!Scan(BuildApk(a)).flagged);
    }
    {
        ApkOpts a;
        a.dex = Dex(8192, true);
        assert(Has(Scan(BuildApk(a)), "entropy"));
    }
    {
        ApkOpts a;
        Set32(a.dex, 0x20, 12345);
        assert(Has(Scan(BuildApk(a)), "header declares 12345"));
    }
    {
        ApkOpts a;
        a.dex[0] = 'x';
        assert(Has(Scan(BuildApk(a)), "DEX magic"));
    }
    {
        ApkOpts a;
        const char stager[] = "Lcom/metasploit/stage/Payload;";
        memcpy(a.dex.data() + 0x200, stager, sizeof(stager) - 1);
        assert(Has(Scan(BuildApk(a)), "Metasploit"));
    }
    {
        std::vector<TestEntry> es = {{"AndroidManifest.xml", Bytes("<manifest/>"), true}};
        assert(Has(Scan(BuildZip(es)), "not valid binary XML"));
    }

    printf("zip_scan_test: all passed\n");
    return 0;
}
