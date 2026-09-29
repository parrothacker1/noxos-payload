#include "file_type.h"

#include <cctype>
#include <cstring>

namespace noxos {
namespace {

constexpr size_t kPdfHeaderWindow = 1024;

bool StartsWith(const std::vector<uint8_t>& b, size_t off, const char* magic, size_t len) {
    return b.size() >= off + len && memcmp(b.data() + off, magic, len) == 0;
}

struct TypeRule {
    const char* key;
    const char* accepted[4];
};

const TypeRule kExtensionRules[] = {
    {"jpg", {"jpeg"}},
    {"jpeg", {"jpeg"}},
    {"png", {"png"}},
    {"gif", {"gif"}},
    {"webp", {"webp"}},
    {"pdf", {"pdf"}},
    {"zip", {"zip", "apk", "ooxml"}},
    {"apk", {"apk"}},
    {"docx", {"ooxml"}},
    {"xlsx", {"ooxml"}},
    {"pptx", {"ooxml"}},
    {"docm", {"ooxml"}},
    {"xlsm", {"ooxml"}},
    {"pptm", {"ooxml"}},
    {"doc", {"ole2"}},
    {"xls", {"ole2"}},
    {"ppt", {"ole2"}},
    {"mp4", {"isobmff"}},
    {"m4a", {"isobmff"}},
    {"mov", {"isobmff"}},
    {"3gp", {"isobmff"}},
    {"heic", {"isobmff"}},
    {"heif", {"isobmff"}},
    {"mp3", {"mp3"}},
    {"ogg", {"ogg"}},
    {"opus", {"ogg"}},
    {"wav", {"wav"}},
    {"rar", {"rar"}},
    {"7z", {"7z"}},
    {"gz", {"gzip"}},
    {"tgz", {"gzip"}},
    {"exe", {"pe"}},
    {"dll", {"pe"}},
    {"so", {"elf"}},
    {"dex", {"dex"}},
};

const TypeRule kMimeRules[] = {
    {"image/jpeg", {"jpeg"}},
    {"image/png", {"png"}},
    {"image/gif", {"gif"}},
    {"image/webp", {"webp"}},
    {"application/pdf", {"pdf"}},
    {"application/zip", {"zip", "apk", "ooxml"}},
    {"application/vnd.android.package-archive", {"apk"}},
    {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", {"ooxml"}},
    {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", {"ooxml"}},
    {"application/vnd.openxmlformats-officedocument.presentationml.presentation", {"ooxml"}},
    {"application/msword", {"ole2"}},
    {"application/vnd.ms-excel", {"ole2"}},
    {"application/vnd.ms-powerpoint", {"ole2"}},
    {"video/mp4", {"isobmff"}},
    {"audio/mp4", {"isobmff"}},
    {"video/quicktime", {"isobmff"}},
    {"video/3gpp", {"isobmff"}},
    {"image/heic", {"isobmff"}},
    {"image/heif", {"isobmff"}},
    {"audio/mpeg", {"mp3"}},
    {"audio/ogg", {"ogg"}},
    {"audio/wav", {"wav"}},
    {"audio/x-wav", {"wav"}},
    {"application/x-rar-compressed", {"rar"}},
    {"application/vnd.rar", {"rar"}},
    {"application/x-7z-compressed", {"7z"}},
    {"application/gzip", {"gzip"}},
};

const char* const kExecutableExtensions[] = {
    "apk", "exe", "scr", "bat", "cmd", "com", "js", "vbs", "sh", "jar", "dex", "so", "hta", "msi",
};

const char* const kDecoyExtensions[] = {
    "jpg", "jpeg", "png", "gif", "webp", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "txt", "mp3", "mp4", "zip",
};

std::string Lower(std::string s) {
    for (char& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

std::vector<std::string> Extensions(const std::string& name) {
    size_t slash = name.find_last_of("/\\");
    std::string base = slash == std::string::npos ? name : name.substr(slash + 1);
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t dot = base.find('.', start);
        if (dot == std::string::npos) break;
        size_t next = base.find('.', dot + 1);
        parts.push_back(Lower(base.substr(dot + 1, next == std::string::npos ? std::string::npos
                                                                             : next - dot - 1)));
        start = dot + 1;
    }
    if (!base.empty() && base[0] == '.' && !parts.empty()) parts.erase(parts.begin());
    return parts;
}

template <size_t N>
bool InList(const std::string& s, const char* const (&list)[N]) {
    for (const char* e : list) {
        if (s == e) return true;
    }
    return false;
}

template <size_t N>
const TypeRule* FindRule(const std::string& key, const TypeRule (&rules)[N]) {
    for (const auto& r : rules) {
        if (key == r.key) return &r;
    }
    return nullptr;
}

const char* const kMediaTypes[] = {
    "jpeg", "png", "gif", "webp", "isobmff", "mp3", "ogg", "wav",
};

bool Accepts(const TypeRule& r, const std::string& actual) {
    for (const char* a : r.accepted) {
        if (a && actual == a) return true;
    }
    return r.accepted[0] && InList(r.accepted[0], kMediaTypes) && InList(actual, kMediaTypes);
}

bool HasBidiControl(const std::string& s) {
    for (size_t i = 0; i + 2 < s.size(); i++) {
        auto b0 = (uint8_t)s[i], b1 = (uint8_t)s[i + 1], b2 = (uint8_t)s[i + 2];
        if (b0 != 0xE2) continue;
        if (b1 == 0x80 && b2 >= 0xAA && b2 <= 0xAE) return true;
        if (b1 == 0x81 && b2 >= 0xA6 && b2 <= 0xA9) return true;
    }
    return false;
}

}  // namespace

const char* DetectFileType(const std::vector<uint8_t>& b) {
    if (StartsWith(b, 0, "\xFF\xD8\xFF", 3)) return "jpeg";
    if (StartsWith(b, 0, "\x89PNG\r\n\x1A\n", 8)) return "png";
    if (StartsWith(b, 0, "GIF87a", 6) || StartsWith(b, 0, "GIF89a", 6)) return "gif";
    if (StartsWith(b, 0, "RIFF", 4) && StartsWith(b, 8, "WEBP", 4)) return "webp";
    if (StartsWith(b, 0, "RIFF", 4) && StartsWith(b, 8, "WAVE", 4)) return "wav";
    if (StartsWith(b, 0, "PK\x03\x04", 4)) return "zip";
    if (StartsWith(b, 0, "\x7F""ELF", 4)) return "elf";
    if (StartsWith(b, 0, "dex\n", 4)) return "dex";
    if (StartsWith(b, 0, "MZ", 2)) return "pe";
    if (StartsWith(b, 0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8)) return "ole2";
    if (StartsWith(b, 0, "Rar!\x1A\x07", 6)) return "rar";
    if (StartsWith(b, 0, "7z\xBC\xAF\x27\x1C", 6)) return "7z";
    if (StartsWith(b, 0, "\x1F\x8B", 2)) return "gzip";
    if (StartsWith(b, 4, "ftyp", 4)) return "isobmff";
    if (StartsWith(b, 0, "OggS", 4)) return "ogg";
    if (StartsWith(b, 0, "ID3", 3) || (b.size() >= 2 && b[0] == 0xFF && (b[1] & 0xE0) == 0xE0)) {
        return "mp3";
    }
    size_t window = b.size() < kPdfHeaderWindow ? b.size() : kPdfHeaderWindow;
    if (window >= 5 && memmem(b.data(), window, "%PDF-", 5) != nullptr) return "pdf";
    return "unknown";
}

CheapFilterResult CheckDeclaredType(const std::string& name, const std::string& mime,
                                    const std::string& actual) {
    CheapFilterResult r;
    if (HasBidiControl(name)) {
        r.flagged = true;
        r.reason = "file name contains a Unicode bidirectional override character";
        return r;
    }

    std::vector<std::string> exts = Extensions(name);
    if (exts.size() >= 2 && InList(exts.back(), kExecutableExtensions) &&
        InList(exts[exts.size() - 2], kDecoyExtensions)) {
        r.flagged = true;
        r.reason = "double extension ." + exts[exts.size() - 2] + "." + exts.back();
        return r;
    }

    if (!exts.empty()) {
        if (const TypeRule* rule = FindRule(exts.back(), kExtensionRules)) {
            if (!Accepts(*rule, actual)) {
                r.flagged = true;
                r.reason = "named ." + exts.back() + " but content is " + actual;
                return r;
            }
        }
    }

    std::string m = Lower(mime.substr(0, mime.find(';')));
    if (const TypeRule* rule = FindRule(m, kMimeRules)) {
        if (!Accepts(*rule, actual)) {
            r.flagged = true;
            r.reason = "declared MIME " + m + " but content is " + actual;
            return r;
        }
    }
    return r;
}

}  // namespace noxos
