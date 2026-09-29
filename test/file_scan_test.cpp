#include "../exif_parser.h"
#include "../file_scan.h"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> Bytes(const std::string& s) { return std::vector<uint8_t>(s.begin(), s.end()); }

void Put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(x & 0xFF);
    v.push_back(x >> 8);
}

void Put32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; i++) v.push_back((x >> (8 * i)) & 0xFF);
}

std::vector<uint8_t> PlainJpeg() {
    std::vector<uint8_t> j = {0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00,
                              0xFF, 0xDA, 0x00, 0x04, 0x00, 0x00};
    for (int i = 0; i < 64; i++) j.push_back((uint8_t)(0x10 + i % 7));
    j.push_back(0xFF);
    j.push_back(0xD9);
    return j;
}

std::vector<uint8_t> StoredZip(const std::vector<std::string>& names) {
    std::vector<uint8_t> z, cd;
    for (const auto& n : names) {
        uint32_t off = (uint32_t)z.size();
        Put32(z, 0x04034b50);
        Put16(z, 20); Put16(z, 0); Put16(z, 0); Put16(z, 0); Put16(z, 0);
        Put32(z, 0); Put32(z, 1); Put32(z, 1);
        Put16(z, (uint16_t)n.size()); Put16(z, 0);
        z.insert(z.end(), n.begin(), n.end());
        z.push_back('x');
        Put32(cd, 0x02014b50);
        Put16(cd, 20); Put16(cd, 20); Put16(cd, 0); Put16(cd, 0); Put16(cd, 0); Put16(cd, 0);
        Put32(cd, 0); Put32(cd, 1); Put32(cd, 1);
        Put16(cd, (uint16_t)n.size()); Put16(cd, 0); Put16(cd, 0); Put16(cd, 0); Put16(cd, 0);
        Put32(cd, 0); Put32(cd, off);
        cd.insert(cd.end(), n.begin(), n.end());
    }
    uint32_t cd_off = (uint32_t)z.size();
    z.insert(z.end(), cd.begin(), cd.end());
    Put32(z, 0x06054b50);
    Put16(z, 0); Put16(z, 0);
    Put16(z, (uint16_t)names.size()); Put16(z, (uint16_t)names.size());
    Put32(z, (uint32_t)cd.size()); Put32(z, cd_off); Put16(z, 0);
    return z;
}

std::vector<uint8_t> Png() { return Bytes(std::string("\x89PNG\r\n\x1A\n", 8) + "IHDR...."); }

noxos::FileScanOutput Scan(const std::vector<uint8_t>& b, const char* name = nullptr,
                           const char* mime = nullptr) {
    std::string n = name ? name : "", m = mime ? mime : "";
    return noxos::ScanFile(b, name ? &n : nullptr, mime ? &m : nullptr);
}

bool Clean(const noxos::FileScanOutput& r, const std::string& json) {
    if (r.status != 0 || r.json != json) {
        fprintf(stderr, "expected clean %s, got %d %s\n", json.c_str(), r.status, r.json.c_str());
        return false;
    }
    return true;
}

bool Flagged(const noxos::FileScanOutput& r, const char* needle) {
    if (r.status != 0 || r.json.find("\"cheap_filter_flagged\":true") == std::string::npos ||
        r.json.find(needle) == std::string::npos) {
        fprintf(stderr, "expected flag \"%s\", got %d %s\n", needle, r.status, r.json.c_str());
        return false;
    }
    return true;
}

}  // namespace

int main() {
    assert(Clean(Scan(PlainJpeg()), "{\"file_type\":\"jpeg\",\"exif\":\"none\"}"));
    {
        std::ifstream f("fuzz/seeds/valid_exif.jpg", std::ios::binary);
        std::vector<uint8_t> jpeg((std::istreambuf_iterator<char>(f)), {});
        assert(!jpeg.empty());
        auto r = Scan(jpeg);
        assert(r.status == 0 && r.json.rfind("{\"file_type\":\"jpeg\",\"", 0) == 0);
    }
    assert(Clean(Scan(Png()), "{\"file_type\":\"png\"}"));
    assert(Clean(Scan(Bytes("just some plain text notes")), "{\"file_type\":\"unknown\"}"));
    assert(Flagged(Scan(Bytes("%PDF-1.7\n1 0 obj\n")), "no %%EOF"));
    {
        auto r = Scan(Bytes("%PDF-1.7\n1 0 obj\n<< >>\nendobj\nxref\nstartxref\n24\n%%EOF\n"));
        assert(r.status == 0 && r.json.rfind("{\"file_type\":\"pdf\",", 0) == 0 &&
               r.json.find("cheap_filter_flagged") == std::string::npos);
    }
    {
        std::vector<uint8_t> bad = {0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x05, 'E', 'x', 'i', 'f', 0, 0};
        auto r = Scan(bad);
        assert(r.status != 0 || r.json.find("\"cheap_filter_flagged\":true") != std::string::npos);
    }
    assert(Flagged(Scan(Bytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")),
                   "EICAR"));
    {
        auto j = PlainJpeg();
        auto z = StoredZip({"a.txt"});
        j.insert(j.end(), z.begin(), z.end());
        assert(Flagged(Scan(j), "ZIP local file header"));
    }
    assert(Scan({}).status == noxos::kStatusMalformedInput);

    {
        std::vector<uint8_t> p;
        std::string name = "cat.jpg", mime = "image/jpeg";
        p.push_back(0); p.push_back((uint8_t)name.size());
        p.insert(p.end(), name.begin(), name.end());
        p.push_back(0); p.push_back((uint8_t)mime.size());
        p.insert(p.end(), mime.begin(), mime.end());
        auto file = PlainJpeg();
        p.insert(p.end(), file.begin(), file.end());
        std::string n, m;
        assert(noxos::StripFileScanMeta(p, n, m));
        assert(n == name && m == mime && p == file);

        std::vector<uint8_t> truncated = {0, 9, 'a'};
        assert(!noxos::StripFileScanMeta(truncated, n, m));
        std::vector<uint8_t> too_long = {0x04, 0x01};
        too_long.resize(2 + 1025, 'a');
        too_long.push_back(0); too_long.push_back(0);
        assert(!noxos::StripFileScanMeta(too_long, n, m));
        std::vector<uint8_t> empty_meta = {0, 0, 0, 0, 'x'};
        assert(noxos::StripFileScanMeta(empty_meta, n, m) && n.empty() && m.empty() &&
               empty_meta == Bytes("x"));
    }

    assert(Clean(Scan(Png(), "cat.jpg", "image/jpeg"), "{\"file_type\":\"png\"}"));
    assert(Clean(Scan(PlainJpeg(), "IMG_0001.JPG", "image/jpeg; q=1"),
                 "{\"file_type\":\"jpeg\",\"exif\":\"none\"}"));
    assert(Flagged(Scan(StoredZip({"a.txt"}), "invoice.pdf", ""), "named .pdf but content is zip"));
    assert(Flagged(Scan(StoredZip({"a.txt"}), "photo.jpg.apk", ""), "double extension .jpg.apk"));
    assert(Flagged(Scan(Png(), "harmless\xE2\x80\xAEgnp.apk", ""), "bidirectional"));
    assert(Flagged(Scan(Bytes("not really an image"), "holiday.jpg", ""), "content is unknown"));
    assert(Flagged(Scan(Png(), "", "application/pdf"), "declared MIME application/pdf"));
    assert(Clean(Scan(StoredZip({"[Content_Types].xml", "word/document.xml"}), "report.docx",
                      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
                 "{\"file_type\":\"ooxml\",\"zip_entries\":2,\"zip_encrypted_entries\":0,"
                 "\"zip_uncompressed_total\":2,\"zip_flag_count\":0,\"ooxml_macros\":false,"
                 "\"ooxml_activex\":0,\"ooxml_embeddings\":0,\"ooxml_external_rels\":0}"));
    assert(Flagged(Scan(StoredZip({"a.txt"}), "report.docx", ""), "named .docx but content is zip"));
    assert(Clean(Scan(StoredZip({"a.txt"}), "archive.zip", "application/octet-stream"),
                 "{\"file_type\":\"zip\",\"zip_entries\":1,\"zip_encrypted_entries\":0,"
                 "\"zip_uncompressed_total\":1,\"zip_flag_count\":0}"));
    assert(Clean(Scan(Bytes("\x7F" "ELFplain"), "libfoo.so", ""), "{\"file_type\":\"elf\"}"));
    assert(Clean(Scan(Bytes("notes"), ".hidden", ""), "{\"file_type\":\"unknown\"}"));

    printf("ok: file_scan_test passed\n");
    return 0;
}
