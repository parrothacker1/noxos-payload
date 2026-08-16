#include "exif_parser.h"

#include <cstring>

namespace noxos {
namespace {

uint16_t ReadU16Be(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

uint16_t ReadU16Le(const uint8_t* p) {
    return (uint16_t)((p[1] << 8) | p[0]);
}

uint32_t ReadU32Be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint32_t ReadU32Le(const uint8_t* p) {
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out += c;
    }
    return out;
}

struct ExifTagDef {
    uint16_t tag;
    const char* name;
};

const ExifTagDef kKnownTags[] = {
    {0x010F, "Make"},
    {0x0110, "Model"},
    {0x0112, "Orientation"},
    {0x011A, "XResolution"},
    {0x011B, "YResolution"},
    {0x0128, "ResolutionUnit"},
    {0x0131, "Software"},
    {0x0132, "DateTime"},
    {0x013B, "Artist"},
    {0x013E, "WhitePoint"},
    {0x013F, "PrimaryChromaticities"},
    {0x0213, "YCbCrPositioning"},
    {0x8298, "Copyright"},
    {0x8769, "ExifIFDPointer"},
    {0x9000, "ExifVersion"},
    {0x9003, "DateTimeOriginal"},
    {0x9004, "DateTimeDigitized"},
    {0x9101, "ComponentsConfiguration"},
    {0x9102, "CompressedBitsPerPixel"},
    {0x9201, "ShutterSpeedValue"},
    {0x9202, "ApertureValue"},
    {0x9204, "ExposureBiasValue"},
    {0x9205, "MaxApertureValue"},
    {0x9207, "MeteringMode"},
    {0x9208, "LightSource"},
    {0x9209, "Flash"},
    {0x920A, "FocalLength"},
    {0xA001, "ColorSpace"},
    {0xA002, "PixelXDimension"},
    {0xA003, "PixelYDimension"},
    {0xA402, "ExposureMode"},
    {0xA403, "WhiteBalance"},
    {0xA404, "DigitalZoomRatio"},
    {0xA405, "FocalLengthIn35mmFilm"},
    {0xA406, "SceneCaptureType"},
    {0xA408, "Contrast"},
    {0xA409, "Saturation"},
    {0xA40A, "Sharpness"},
    {0xA433, "LensMake"},
    {0xA434, "LensModel"},
    {0x8825, "GPSInfoIFDPointer"},
};

const char* ExifTagName(uint16_t tag) {
    for (size_t i = 0; i < sizeof(kKnownTags) / sizeof(kKnownTags[0]); i++) {
        if (kKnownTags[i].tag == tag) return kKnownTags[i].name;
    }
    return nullptr;
}

size_t ExifTypeSize(uint16_t type) {
    switch (type) {
        case 1: return 1;
        case 2: return 1;
        case 3: return 2;
        case 4: return 4;
        case 5: return 8;
        case 7: return 1;
        case 9: return 4;
        case 10: return 8;
        default: return 0;
    }
}

std::string ReadIfdValue(const uint8_t* tiff_base, size_t tiff_len,
                          const uint8_t* entry, bool little_endian) {
    auto u16 = little_endian ? ReadU16Le : ReadU16Be;
    auto u32 = little_endian ? ReadU32Le : ReadU32Be;

    uint16_t type = u16(entry + 2);
    uint32_t count = u32(entry + 4);
    size_t tsz = ExifTypeSize(type);

    if (tsz == 0 || count == 0) return "";

    size_t total = tsz * (size_t)count;
    const uint8_t* vp;
    if (total <= 4) {
        vp = entry + 8;
    } else {
        size_t offset = u32(entry + 8);
        if (offset + total > tiff_len) return "";
        vp = tiff_base + offset;
    }

    char buf[64];
    switch (type) {
        case 2: {
            std::string s(reinterpret_cast<const char*>(vp), count);
            while (!s.empty() && s.back() == '\0') s.pop_back();
            return s;
        }
        case 3: {
            if (count == 1) {
                snprintf(buf, sizeof(buf), "%u", u16(vp));
                return buf;
            }
            snprintf(buf, sizeof(buf), "%u,%u", u16(vp),
                     (count > 1 && 2 * 1 + 2 <= (int)total) ? u16(vp + 2) : 0u);
            return buf;
        }
        case 4: {
            snprintf(buf, sizeof(buf), "%u", u32(vp));
            return buf;
        }
        case 5:
        case 10: {
            if (total < 8) return "";
            uint32_t num = u32(vp);
            uint32_t den = u32(vp + 4);
            if (den == 0) return "0";
            snprintf(buf, sizeof(buf), "%u/%u", num, den);
            return buf;
        }
        default:
            return "";
    }
}

void WalkIfd(const uint8_t* tiff_base, size_t tiff_len, uint32_t ifd_offset,
             bool little_endian,
             std::vector<std::pair<std::string, std::string>>& out_pairs,
             int depth) {
    size_t offset = ifd_offset;
    if (depth > 2 || offset + 2 > tiff_len) return;

    auto u16 = little_endian ? ReadU16Le : ReadU16Be;
    auto u32 = little_endian ? ReadU32Le : ReadU32Be;

    uint16_t entry_count = u16(tiff_base + offset);
    size_t pos = offset + 2;

    for (uint16_t i = 0; i < entry_count; i++) {
        if (pos + 12 > tiff_len) break;

        const uint8_t* entry = tiff_base + pos;
        uint16_t tag = u16(entry);

        const char* name = ExifTagName(tag);
        if (name) {
            if (tag == 0x8769 || tag == 0x8825) {
                uint32_t sub_offset = u32(entry + 8);
                WalkIfd(tiff_base, tiff_len, sub_offset, little_endian,
                        out_pairs, depth + 1);
            } else {
                std::string val =
                    ReadIfdValue(tiff_base, tiff_len, entry, little_endian);
                if (!val.empty()) {
                    out_pairs.push_back({name, val});
                }
            }
        }

        pos += 12;
    }
}

}  // namespace

int ParseExif(const std::vector<uint8_t>& file_bytes, std::string& out_json) {
    const uint8_t* data = file_bytes.data();
    size_t size = file_bytes.size();

    if (size < 4 || data[0] != 0xFF || data[1] != 0xD8) {
        out_json = "{\"error\":\"not a JPEG file\"}";
        return kStatusMalformedInput;
    }

    size_t pos = 2;
    while (pos + 4 <= size) {
        if (data[pos] != 0xFF) {
            out_json = "{\"error\":\"invalid JPEG segment marker\"}";
            return kStatusParseError;
        }

        uint8_t marker = data[pos + 1];
        uint16_t seg_len = ReadU16Be(data + pos + 2);

        if (marker == 0xE1 && pos + 4 + 6 <= size) {
            if (memcmp(data + pos + 4, "Exif\0\0", 6) == 0) {
                if (seg_len < 8 || pos + 2 + (size_t)seg_len > size) {
                    out_json = "{\"error\":\"invalid APP1 segment length\"}";
                    return kStatusParseError;
                }

                const uint8_t* tiff = data + pos + 10;
                size_t tiff_len = (size_t)seg_len - 8;

                if (tiff_len < 8) {
                    out_json = "{\"error\":\"truncated TIFF header\"}";
                    return kStatusParseError;
                }

                bool little_endian = (tiff[0] == 'I' && tiff[1] == 'I');
                bool big_endian = (tiff[0] == 'M' && tiff[1] == 'M');
                if (!little_endian && !big_endian) {
                    out_json = "{\"error\":\"invalid TIFF byte order marker\"}";
                    return kStatusParseError;
                }

                auto u32 = little_endian ? ReadU32Le : ReadU32Be;
                uint32_t ifd0_offset = u32(tiff + 4);

                std::vector<std::pair<std::string, std::string>> pairs;
                WalkIfd(tiff, tiff_len, ifd0_offset, little_endian, pairs, 0);

                if (pairs.empty()) {
                    out_json = "{\"error\":\"no readable EXIF tags found\"}";
                    return kStatusParseError;
                }

                std::string json = "{";
                for (size_t k = 0; k < pairs.size(); k++) {
                    if (k > 0) json += ",";
                    json += "\"" + JsonEscape(pairs[k].first) + "\":";
                    json += "\"" + JsonEscape(pairs[k].second) + "\"";
                }
                json += "}";
                out_json = json;
                return kStatusOk;
            }
        }

        pos += 2 + seg_len;
    }

    out_json = "{\"error\":\"no EXIF APP1 segment found in JPEG\"}";
    return kStatusParseError;
}

}  // namespace noxos
