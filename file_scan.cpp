#include "file_scan.h"

#include "exif_parser.h"
#include "file_cheap_filter.h"
#include "file_type.h"
#include "image_scan.h"
#include "json_util.h"
#include "pdf_scan.h"
#include "zip_scan.h"

namespace noxos {
namespace {

const char kNoExifSegment[] = "{\"error\":\"no EXIF APP1 segment found in JPEG\"}";
const char kNoExifTags[] = "{\"error\":\"no readable EXIF tags found\"}";

uint16_t ReadU16Be(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

std::string TypeOnlyJson(const std::string& type) {
    return "{\"file_type\":\"" + JsonEscape(type) + "\"}";
}

}  // namespace

bool StripFileScanMeta(std::vector<uint8_t>& payload, std::string& name, std::string& mime) {
    size_t pos = 0;
    auto take = [&](std::string& out, size_t max_len) {
        if (payload.size() - pos < 2) return false;
        size_t len = ReadU16Be(payload.data() + pos);
        pos += 2;
        if (len > max_len || payload.size() - pos < len) return false;
        out.assign(reinterpret_cast<const char*>(payload.data() + pos), len);
        pos += len;
        return true;
    };
    if (!take(name, kMaxDeclaredNameBytes) || !take(mime, kMaxDeclaredMimeBytes)) return false;
    payload.erase(payload.begin(), payload.begin() + (ptrdiff_t)pos);
    return true;
}

FileScanOutput ScanFile(const std::vector<uint8_t>& b, const std::string* name,
                        const std::string* mime) {
    if (b.empty()) return {kStatusMalformedInput, "{\"error\":\"file size out of range\"}"};

    FileScanOutput out{kStatusOk, ""};
    CheapFilterResult cheap;
    std::string type = DetectFileType(b);
    bool is_jpeg = b.size() >= 2 && b[0] == 0xFF && b[1] == 0xD8;

    if (!is_jpeg && LooksLikeZip(b)) {
        cheap = ScanZip(b, out.json, &type);
    } else if (is_jpeg) {
        type = "jpeg";
        out.status = (uint8_t)ParseExif(b, out.json);
        cheap = CheckFileCheapFilter(b);
        bool exif_absent = out.json == kNoExifSegment || out.json == kNoExifTags;
        if (out.status == kStatusOk) {
            out.json.insert(1, out.json.size() > 2 ? "\"file_type\":\"jpeg\"," : "\"file_type\":\"jpeg\"");
        } else if (cheap.flagged || (out.status == kStatusParseError && exif_absent)) {
            out.status = kStatusOk;
            out.json = exif_absent ? "{\"file_type\":\"jpeg\",\"exif\":\"none\"}" : TypeOnlyJson(type);
        }
    } else if (type == "pdf") {
        cheap = ScanPdf(b, out.json);
    } else if (type == "png" || type == "gif" || type == "webp") {
        cheap = ScanImage(b, type, out.json);
    } else {
        cheap = CheckFileCheapFilter(b);
        out.json = TypeOnlyJson(type);
    }

    if (out.status == kStatusOk && !cheap.flagged && (name || mime)) {
        cheap = CheckDeclaredType(name ? *name : "", mime ? *mime : "", type);
    }

    if (out.status == kStatusOk && cheap.flagged) {
        out.json.pop_back();
        if (out.json.size() > 1) out.json += ",";
        out.json += "\"cheap_filter_flagged\":true,\"cheap_filter_reason\":\"" +
                    JsonEscape(cheap.reason) + "\"}";
    }
    return out;
}

}  // namespace noxos
