#include "../exif_parser.h"

#include <cassert>
#include <cstdio>
#include <vector>

namespace {

void PushBe16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back((x >> 8) & 0xFF);
    v.push_back(x & 0xFF);
}

void PushLe16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(x & 0xFF);
    v.push_back((x >> 8) & 0xFF);
}

void PushLe32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(x & 0xFF);
    v.push_back((x >> 8) & 0xFF);
    v.push_back((x >> 16) & 0xFF);
    v.push_back((x >> 24) & 0xFF);
}

std::vector<uint8_t> BuildTiffWithMakeTag() {
    std::vector<uint8_t> tiff;
    tiff.push_back('I');
    tiff.push_back('I');
    PushLe16(tiff, 42);
    PushLe32(tiff, 8);

    PushLe16(tiff, 1);
    PushLe16(tiff, 0x010F);
    PushLe16(tiff, 2);
    PushLe32(tiff, 4);
    tiff.push_back('N');
    tiff.push_back('o');
    tiff.push_back('x');
    tiff.push_back('\0');
    PushLe32(tiff, 0);

    return tiff;
}

std::vector<uint8_t> WrapAsApp1(const std::vector<uint8_t>& tiff, int seg_len_override = -1) {
    std::vector<uint8_t> jpeg = {0xFF, 0xD8, 0xFF, 0xE1};
    uint16_t seg_len = seg_len_override >= 0
                            ? (uint16_t)seg_len_override
                            : (uint16_t)(2 + 6 + tiff.size());
    PushBe16(jpeg, seg_len);
    jpeg.push_back('E');
    jpeg.push_back('x');
    jpeg.push_back('i');
    jpeg.push_back('f');
    jpeg.push_back('\0');
    jpeg.push_back('\0');
    jpeg.insert(jpeg.end(), tiff.begin(), tiff.end());
    return jpeg;
}

}  // namespace

int main() {
    {
        auto jpeg = WrapAsApp1(BuildTiffWithMakeTag());
        std::string json;
        int status = noxos::ParseExif(jpeg, json);
        assert(status == noxos::kStatusOk);
        assert(json.find("\"Make\":\"Nox\"") != std::string::npos);
    }

    {
        std::vector<uint8_t> empty;
        std::string json;
        int status = noxos::ParseExif(empty, json);
        assert(status == noxos::kStatusMalformedInput);
    }

    {
        std::vector<uint8_t> not_jpeg = {0x00, 0x01, 0x02, 0x03};
        std::string json;
        int status = noxos::ParseExif(not_jpeg, json);
        assert(status == noxos::kStatusMalformedInput);
    }

    {
        std::vector<uint8_t> no_app1 = {0xFF, 0xD8, 0xFF, 0xD9};
        std::string json;
        int status = noxos::ParseExif(no_app1, json);
        assert(status == noxos::kStatusParseError);
    }

    {
        auto jpeg = WrapAsApp1(BuildTiffWithMakeTag(), /*seg_len_override=*/4);
        std::string json;
        int status = noxos::ParseExif(jpeg, json);
        assert(status == noxos::kStatusParseError);
        assert(json.find("invalid APP1 segment length") != std::string::npos);
    }

    {
        auto jpeg = WrapAsApp1(BuildTiffWithMakeTag(), /*seg_len_override=*/60000);
        std::string json;
        int status = noxos::ParseExif(jpeg, json);
        assert(status == noxos::kStatusParseError);
        assert(json.find("invalid APP1 segment length") != std::string::npos);
    }

    {
        auto jpeg = WrapAsApp1(BuildTiffWithMakeTag(), /*seg_len_override=*/10);
        std::string json;
        int status = noxos::ParseExif(jpeg, json);
        assert(status == noxos::kStatusParseError);
        assert(json.find("truncated TIFF header") != std::string::npos);
    }

    {
        std::vector<uint8_t> bad_tiff = {'X', 'X', 0, 42, 8, 0, 0, 0};
        auto jpeg = WrapAsApp1(bad_tiff);
        std::string json;
        int status = noxos::ParseExif(jpeg, json);
        assert(status == noxos::kStatusParseError);
        assert(json.find("invalid TIFF byte order marker") != std::string::npos);
    }

    {
        std::vector<uint8_t> fuzzer_found_crash = {
            0xff, 0xd8, 0xff, 0xe1, 0x00, 0x2d, 0x45, 0x78, 0x69, 0x66, 0x00, 0x00,
        };
        std::string json;
        int status = noxos::ParseExif(fuzzer_found_crash, json);
        assert(status == noxos::kStatusParseError);
    }

    printf("ok: exif_parser_test passed\n");
    return 0;
}
