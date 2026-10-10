#include "../ole2_scan.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<uint8_t>;

void Put16(Bytes& v, uint16_t x) {
    v.push_back(x & 0xFF);
    v.push_back(x >> 8);
}

void Put32(Bytes& v, uint32_t x) {
    for (int i = 0; i < 4; i++) v.push_back((x >> (8 * i)) & 0xFF);
}

void Set32(Bytes& v, size_t at, uint32_t x) {
    for (int i = 0; i < 4; i++) v[at + i] = (x >> (8 * i)) & 0xFF;
}

struct Entry {
    std::string name;
    uint8_t type;
    uint32_t start = 0xFFFFFFFE;
    uint32_t size = 0;
};

Bytes Biff(const std::vector<std::pair<uint8_t, uint8_t>>& sheets, bool file_pass = false) {
    Bytes d;
    Put16(d, 0x0809);
    Put16(d, 16);
    d.insert(d.end(), 16, 0);
    if (file_pass) {
        Put16(d, 0x002F);
        Put16(d, 4);
        d.insert(d.end(), 4, 0);
    }
    for (const auto& s : sheets) {
        Put16(d, 0x0085);
        Put16(d, 10);
        Put32(d, 0);
        d.push_back(s.first);
        d.push_back(s.second);
        d.push_back(2);
        d.push_back(0);
        d.push_back('S');
        d.push_back('1');
    }
    Put16(d, 0x000A);
    Put16(d, 0);
    while (d.size() < 4200) d.push_back(0);
    return d;
}

Bytes BuildCfb(std::vector<Entry> entries, const Bytes* workbook = nullptr) {
    size_t wb_sectors = workbook ? (workbook->size() + 511) / 512 : 0;
    if (workbook) {
        for (auto& e : entries) {
            if (e.name == "Workbook") {
                e.start = 2;
                e.size = (uint32_t)workbook->size();
            }
        }
    }
    Bytes fat(512, 0xFF);
    auto set_fat = [&](size_t i, uint32_t v) { Set32(fat, i * 4, v); };
    set_fat(0, 0xFFFFFFFD);
    set_fat(1, 0xFFFFFFFE);
    for (size_t i = 0; i < wb_sectors; i++) set_fat(2 + i, i + 1 == wb_sectors ? 0xFFFFFFFE : (uint32_t)(3 + i));

    Bytes dir;
    Entry root{"Root Entry", 5};
    std::vector<Entry> all = {root};
    all.insert(all.end(), entries.begin(), entries.end());
    for (const auto& e : all) {
        size_t start = dir.size();
        for (char c : e.name) {
            dir.push_back((uint8_t)c);
            dir.push_back(0);
        }
        dir.resize(start + 64, 0);
        Put16(dir, (uint16_t)((e.name.size() + 1) * 2));
        dir.push_back(e.type);
        dir.push_back(1);
        Put32(dir, 0xFFFFFFFF);
        Put32(dir, 0xFFFFFFFF);
        Put32(dir, 0xFFFFFFFF);
        dir.resize(start + 116, 0);
        Put32(dir, e.start);
        Put32(dir, e.size);
        Put32(dir, 0);
    }
    dir.resize(512, 0);

    Bytes h = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    h.resize(24, 0);
    Put16(h, 0x3E);
    Put16(h, 3);
    Put16(h, 0xFFFE);
    Put16(h, 9);
    Put16(h, 6);
    h.resize(44, 0);
    Put32(h, 1);
    Put32(h, 1);
    Put32(h, 0);
    Put32(h, 4096);
    Put32(h, 0xFFFFFFFE);
    Put32(h, 0);
    Put32(h, 0xFFFFFFFE);
    Put32(h, 0);
    Put32(h, 0);
    h.resize(512, 0xFF);

    Bytes out = h;
    out.insert(out.end(), fat.begin(), fat.end());
    out.insert(out.end(), dir.begin(), dir.end());
    if (workbook) {
        Bytes padded = *workbook;
        padded.resize(wb_sectors * 512, 0);
        out.insert(out.end(), padded.begin(), padded.end());
    }
    return out;
}

noxos::CheapFilterResult Scan(const Bytes& b, std::string* json = nullptr) {
    std::string j;
    auto r = noxos::ScanOle2(b, j);
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
        auto r = Scan(BuildCfb({{"WordDocument", 2}, {"1Table", 2}}), &j);
        if (r.flagged) fprintf(stderr, "%s\n", r.reason.c_str());
        assert(!r.flagged);
        assert(j == "{\"file_type\":\"ole2\",\"ole2_header_ok\":true,\"ole2_sector_size\":512,"
                    "\"ole2_entries\":3,\"ole2_macros\":false,\"ole2_xlm_sheets\":0,"
                    "\"ole2_encrypted\":false,\"ole2_embedded_objects\":0,"
                    "\"ole2_equation_objects\":0,\"ole2_flag_count\":0}");
    }
    assert(Has(Scan(BuildCfb({{"WordDocument", 2}, {"VBA", 1}, {"_VBA_PROJECT", 2}})), "VBA project"));
    assert(Has(Scan(BuildCfb({{"Workbook", 2}, {"_VBA_PROJECT_CUR", 1}})), "VBA project"));
    assert(Has(Scan(BuildCfb({{"WordDocument", 2}, {"Macros", 1}})), "VBA project"));
    {
        std::string j;
        auto r = Scan(BuildCfb({{"EncryptionInfo", 2}, {"EncryptedPackage", 2}}), &j);
        assert(Has(r, "encrypted"));
        assert(j.find("\"ole2_encrypted\":true") != std::string::npos);
    }
    {
        Bytes wb = Biff({{0, 0}, {0, 0}});
        assert(!Scan(BuildCfb({{"Workbook", 2}, {"SummaryInformation", 2}}, &wb)).flagged);
        wb = Biff({{0, 0}, {0, 1}});
        std::string j;
        auto r = Scan(BuildCfb({{"Workbook", 2}}, &wb), &j);
        assert(Has(r, "an Excel 4.0 (XLM) macro sheet"));
        assert(j.find("\"ole2_xlm_sheets\":1") != std::string::npos);
        wb = Biff({{1, 1}});
        assert(Has(Scan(BuildCfb({{"Workbook", 2}}, &wb)), "a hidden Excel 4.0 (XLM) macro sheet"));
        wb = Biff({{0, 6}});
        assert(Has(Scan(BuildCfb({{"Workbook", 2}}, &wb)), "VBA project"));
        wb = Biff({{0, 0}}, true);
        assert(Has(Scan(BuildCfb({{"Workbook", 2}}, &wb)), "encrypted"));
    }
    {
        std::string j;
        Scan(BuildCfb({{"\x01Ole10Native", 2}, {"ObjectPool", 1}, {"Equation Native", 2}}), &j);
        assert(j.find("\"ole2_embedded_objects\":2") != std::string::npos);
        assert(j.find("\"ole2_equation_objects\":1") != std::string::npos);
    }
    {
        Bytes b = BuildCfb({{"WordDocument", 2}});
        b[28] = 0;
        assert(Has(Scan(b), "inconsistent version"));
        b = BuildCfb({{"WordDocument", 2}});
        b[30] = 12;
        assert(Has(Scan(b), "inconsistent version"));
        b = BuildCfb({{"WordDocument", 2}});
        Set32(b, 512 + 4, 1);
        assert(Has(Scan(b), "loops"));
        b = BuildCfb({{"WordDocument", 2}});
        b.resize(1100);
        assert(Has(Scan(b), "leaves the file"));
        b = BuildCfb({{"WordDocument", 2}});
        Set32(b, 76, 9999);
        assert(Has(Scan(b), "FAT sector lies outside"));
        assert(Has(Scan(Bytes(300, 0xD0)), "shorter than"));
    }
    {
        Bytes b = BuildCfb({{"WordDocument", 2}});
        b.insert(b.end(), 4000, 0);
        b.push_back(0x7F);
        b.push_back('E');
        b.push_back('L');
        b.push_back('F');
        assert(Has(Scan(b), "embedded ELF executable signature after the last used OLE2 sector"));
        b = BuildCfb({{"WordDocument", 2}});
        b.insert(b.end(), 4000, 0);
        assert(!Scan(b).flagged);
    }
    {
        Bytes b = BuildCfb({{"WordDocument", 2}});
        const char* eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        b.insert(b.end(), eicar, eicar + strlen(eicar));
        assert(Has(Scan(b), "EICAR"));
    }

    printf("ok: ole2_scan_test passed\n");
    return 0;
}
