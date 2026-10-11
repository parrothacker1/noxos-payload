#include "../image_scan.h"

#include <zlib.h>

#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<uint8_t>;

void PutBe32(Bytes& v, uint32_t x) {
    for (int i = 3; i >= 0; i--) v.push_back((x >> (8 * i)) & 0xFF);
}

void PutLe32(Bytes& v, uint32_t x) {
    for (int i = 0; i < 4; i++) v.push_back((x >> (8 * i)) & 0xFF);
}

void Append(Bytes& v, const std::string& s) { v.insert(v.end(), s.begin(), s.end()); }

void PngChunk(Bytes& v, const std::string& type, const Bytes& data, bool bad_crc = false) {
    PutBe32(v, (uint32_t)data.size());
    size_t start = v.size();
    Append(v, type);
    v.insert(v.end(), data.begin(), data.end());
    uint32_t crc = (uint32_t)crc32(0L, v.data() + start, (uInt)(v.size() - start));
    PutBe32(v, bad_crc ? crc ^ 1 : crc);
}

Bytes Png(uint32_t w, uint32_t h, bool with_iend = true, bool bad_crc = false) {
    Bytes v = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    Bytes ihdr;
    PutBe32(ihdr, w);
    PutBe32(ihdr, h);
    for (uint8_t b : {8, 2, 0, 0, 0}) ihdr.push_back(b);
    PngChunk(v, "IHDR", ihdr);
    PngChunk(v, "IDAT", Bytes(20, 0x55), bad_crc);
    if (with_iend) PngChunk(v, "IEND", {});
    return v;
}

Bytes Gif(bool with_trailer = true) {
    Bytes v;
    Append(v, "GIF89a");
    for (uint8_t b : {1, 0, 1, 0, 0x80, 0, 0, 0xFF, 0xFF, 0xFF, 0, 0, 0}) v.push_back(b);
    for (uint8_t b : {0x21, 0xF9, 4, 0, 0, 0, 0, 0}) v.push_back(b);
    for (uint8_t b : {0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x44, 1, 0}) v.push_back(b);
    if (with_trailer) v.push_back(0x3B);
    return v;
}

Bytes Webp(uint32_t riff_extra = 0) {
    Bytes body;
    Append(body, "WEBP");
    Append(body, "VP8L");
    PutLe32(body, 5);
    for (int i = 0; i < 5; i++) body.push_back(0x2F);
    body.push_back(0);
    Bytes v;
    Append(v, "RIFF");
    PutLe32(v, (uint32_t)body.size() + riff_extra);
    v.insert(v.end(), body.begin(), body.end());
    return v;
}

Bytes PngWith(const std::vector<std::pair<std::string, Bytes>>& chunks) {
    Bytes v = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    for (const auto& c : chunks) PngChunk(v, c.first, c.second);
    return v;
}

Bytes Ihdr() {
    Bytes ihdr;
    PutBe32(ihdr, 8);
    PutBe32(ihdr, 8);
    for (uint8_t b : {8, 2, 0, 0, 0}) ihdr.push_back(b);
    return ihdr;
}

Bytes GifWithExtension(uint8_t label, size_t n) {
    Bytes g = Gif();
    g.pop_back();
    g.push_back(0x21);
    g.push_back(label);
    size_t left = n;
    while (left > 0) {
        size_t take = left > 255 ? 255 : left;
        g.push_back((uint8_t)take);
        g.insert(g.end(), take, 'c');
        left -= take;
    }
    g.push_back(0);
    g.push_back(0x3B);
    return g;
}

noxos::CheapFilterResult Scan(const Bytes& b, const std::string& type, std::string* json = nullptr) {
    std::string j;
    auto r = noxos::ScanImage(b, type, j);
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
        auto r = Scan(Png(64, 32), "png", &j);
        assert(!r.flagged);
        assert(j == "{\"file_type\":\"png\",\"image_width\":64,\"image_height\":32,\"image_chunks\":3,"
                    "\"image_trailing_bytes\":0,\"image_crc_errors\":0,\"image_structure_ok\":true,"
                    "\"image_idat_chunks\":1,\"image_text_bytes\":0,\"image_unknown_bytes\":0}");
    }
    assert(Has(Scan(Png(64, 32, true, true), "png"), "1 PNG chunk CRC mismatches"));
    assert(Has(Scan(Png(64, 32, false), "png"), "no IEND"));
    {
        Bytes p = Png(64, 32);
        p.resize(p.size() - 20);
        assert(Has(Scan(p, "png"), "file ends first"));
        p = Png(64, 32);
        p[8 + 3] = 0xFF;
        assert(Has(Scan(p, "png"), "file ends first"));
    }
    {
        Bytes p = Png(64, 32);
        Append(p, "PK\x03\x04 payload");
        assert(Has(Scan(p, "png"), "embedded ZIP local file header"));
        p = Png(64, 32);
        p.insert(p.end(), 5000, 'x');
        assert(Has(Scan(p, "png"), "5000 bytes of unexplained trailing data"));
        p = Png(64, 32);
        p.insert(p.end(), 100, 0);
        assert(!Scan(p, "png").flagged);
    }
    assert(Has(Scan(Png(70000, 70000), "png"), "70000x70000 pixels"));
    {
        Bytes p = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
        PngChunk(p, "IDAT", Bytes(4, 1));
        assert(Has(Scan(p, "png"), "IHDR"));
    }

    {
        std::string j;
        auto r = Scan(Gif(), "gif", &j);
        if (r.flagged) fprintf(stderr, "%s\n", r.reason.c_str());
        assert(!r.flagged);
        assert(j.find("\"image_chunks\":1") != std::string::npos);
        assert(Has(Scan(Gif(false), "gif"), "no trailer"));
        Bytes g = Gif();
        g.resize(g.size() - 4);
        assert(Has(Scan(g, "gif"), "runs past the end"));
        g = Gif();
        Append(g, "\x7F""ELF trailing");
        assert(Has(Scan(g, "gif"), "embedded ELF executable"));
        g = Gif();
        g.insert(g.end() - 1, 0x99);
        assert(Has(Scan(g, "gif"), "unknown block type"));
    }

    {
        std::string j;
        auto r = Scan(Webp(), "webp", &j);
        assert(!r.flagged);
        assert(j.find("\"image_chunks\":1") != std::string::npos);
        assert(Has(Scan(Webp(50), "webp"), "declares"));
        Bytes w = Webp();
        Append(w, "%PDF-1.4 hidden");
        assert(Has(Scan(w, "webp"), "embedded PDF"));
        w = Webp();
        w[12] = 'X';
        assert(Has(Scan(w, "webp"), "VP8/VP8L/VP8X"));
        w = Webp();
        w[16] = 0xFF;
        assert(Has(Scan(w, "webp"), "runs past the RIFF size"));
    }

    {
        Bytes idat(20, 0x55);
        std::string j;
        auto r = Scan(PngWith({{"IHDR", Ihdr()}, {"tEXt", Bytes(200, 'k')}, {"prVW", Bytes(100, 1)},
                               {"IDAT", idat}, {"IEND", {}}}), "png", &j);
        if (r.flagged) fprintf(stderr, "%s\n", r.reason.c_str());
        assert(!r.flagged);
        assert(j.find("\"image_text_bytes\":200") != std::string::npos);
        assert(j.find("\"image_unknown_bytes\":100") != std::string::npos);
        assert(Has(Scan(PngWith({{"IHDR", Ihdr()}, {"IDAT", idat}, {"PLTE", Bytes(6, 0)}, {"IEND", {}}}), "png"),
                     "PLTE chunk appears after the image data"));
        assert(Has(Scan(PngWith({{"IHDR", Ihdr()}, {"IDAT", idat}, {"tIME", Bytes(7, 0)}, {"IDAT", idat}, {"IEND", {}}}),
                        "png"), "IDAT chunks are not contiguous"));
        assert(!Scan(PngWith({{"IHDR", Ihdr()}, {"IDAT", idat}, {"IDAT", idat}, {"IEND", {}}}), "png").flagged);
        assert(Has(Scan(PngWith({{"IHDR", Ihdr()}, {"XTRA", Bytes(4, 0)}, {"IDAT", idat}, {"IEND", {}}}), "png"),
                   "unknown critical chunk XTRA"));
        assert(Has(Scan(PngWith({{"IHDR", Ihdr()}, {"IDAT", idat}, {"zzZz", Bytes(70000, 1)}, {"IEND", {}}}), "png"),
                   "70000-byte unknown ancillary chunk zzZz"));
        assert(Has(Scan(PngWith({{"IHDR", Ihdr()}, {"tEXt", Bytes(1048577, 'a')}, {"IDAT", idat}, {"IEND", {}}}), "png"),
                   "tEXt chunk is 1048577 bytes"));
        assert(!Scan(PngWith({{"IHDR", Ihdr()}, {"iCCP", Bytes(200000, 1)}, {"IDAT", idat}, {"IEND", {}}}), "png").flagged);
        assert(Has(Scan(PngWith({{"IHDR", Ihdr()}, {"IHDR", Ihdr()}, {"IDAT", idat}, {"IEND", {}}}), "png"),
                   "more than one IHDR"));
        assert(Has(Scan(PngWith({{"IHDR", Ihdr()}, {"IEND", {}}}), "png"), "no IDAT chunk"));

        assert(!Scan(GifWithExtension(0xFE, 500), "gif").flagged);
        assert(Has(Scan(GifWithExtension(0xFE, 70000), "gif"), "GIF comment extension is 70000 bytes"));
        assert(!Scan(GifWithExtension(0xFF, 20000), "gif").flagged);
        assert(Has(Scan(GifWithExtension(0xFF, 300000), "gif"), "GIF application extension is 300000 bytes"));
        std::string gj;
        Scan(GifWithExtension(0xFE, 500), "gif", &gj);
        assert(gj.find("\"image_text_bytes\":500") != std::string::npos);
    }

    printf("ok: image_scan_test passed\n");
    return 0;
}
