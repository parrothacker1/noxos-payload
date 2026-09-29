#include "pdf_scan.h"

#include <zlib.h>

#include <algorithm>
#include <cctype>
#include <cstring>

#include "json_util.h"
#include "scan_util.h"

namespace noxos {
namespace {

constexpr size_t kHeaderWindow = 1024;
constexpr size_t kMaxTrailingBytes = 1024;
constexpr size_t kMaxStreamOutput = 1024 * 1024;
constexpr size_t kMaxTotalInflated = 16 * 1024 * 1024;
constexpr size_t kMaxStreams = 4096;
constexpr size_t kMaxNameLen = 127;

enum Keyword {
    kJs, kJavaScript, kOpenAction, kAa, kLaunch, kEmbeddedFile, kRichMedia, kXfa,
    kObjStm, kAcroForm, kJbig2Decode, kUri, kSubmitForm, kGoToR, kKeywordCount
};

const char* const kKeywordNames[kKeywordCount] = {
    "JS", "JavaScript", "OpenAction", "AA", "Launch", "EmbeddedFile", "RichMedia", "XFA",
    "ObjStm", "AcroForm", "JBIG2Decode", "URI", "SubmitForm", "GoToR",
};

const char* const kKeywordJsonKeys[kKeywordCount] = {
    "pdf_js", "pdf_javascript", "pdf_openaction", "pdf_aa", "pdf_launch", "pdf_embeddedfile",
    "pdf_richmedia", "pdf_xfa", "pdf_objstm", "pdf_acroform", "pdf_jbig2decode", "pdf_uri",
    "pdf_submitform", "pdf_gotor",
};

struct Counts {
    size_t keywords[kKeywordCount] = {};
    size_t obfuscated = 0;
    std::string first_obfuscated;
    size_t streams = 0;
    size_t inflated_streams = 0;
    size_t inflated_bytes = 0;
    const char* signature = nullptr;
};

bool IsDelimiter(uint8_t c) {
    return c <= 0x20 || c == '/' || c == '(' || c == ')' || c == '<' || c == '>' || c == '[' ||
           c == ']' || c == '{' || c == '}' || c == '%' || c == 0x7F;
}

int HexVal(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void CountNames(const uint8_t* p, size_t n, Counts& c) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != '/') continue;
        std::string name;
        bool escaped = false;
        size_t j = i + 1;
        while (j < n && !IsDelimiter(p[j]) && name.size() <= kMaxNameLen) {
            if (p[j] == '#' && j + 2 < n && HexVal(p[j + 1]) >= 0 && HexVal(p[j + 2]) >= 0) {
                name += (char)(HexVal(p[j + 1]) * 16 + HexVal(p[j + 2]));
                escaped = true;
                j += 3;
            } else {
                name += (char)p[j++];
            }
        }
        i = j - 1;
        for (int k = 0; k < kKeywordCount; k++) {
            if (name != kKeywordNames[k]) continue;
            c.keywords[k]++;
            if (escaped) {
                if (c.obfuscated++ == 0) c.first_obfuscated = name;
            }
        }
    }
}

bool LooksLikeZlib(const uint8_t* p, size_t n) {
    return n >= 2 && (p[0] & 0x0F) == 8 && (p[0] >> 4) <= 7 && ((p[0] << 8) | p[1]) % 31 == 0;
}

void InflateStreams(const std::vector<uint8_t>& b, Counts& c) {
    std::vector<uint8_t> out;
    size_t pos = 0;
    while (c.streams < kMaxStreams && b.size() - pos >= 6) {
        const void* hit = memmem(b.data() + pos, b.size() - pos, "stream", 6);
        if (!hit) break;
        size_t kw = (size_t)((const uint8_t*)hit - b.data());
        pos = kw + 6;
        if (kw >= 3 && memcmp(b.data() + kw - 3, "end", 3) == 0) continue;
        size_t start = pos;
        if (start < b.size() && b[start] == '\r') start++;
        if (start < b.size() && b[start] == '\n') start++;
        if (start == pos) continue;
        const void* end_hit = memmem(b.data() + start, b.size() - start, "endstream", 9);
        size_t end = end_hit ? (size_t)((const uint8_t*)end_hit - b.data()) : b.size();
        c.streams++;
        pos = end;
        if (c.inflated_bytes >= kMaxTotalInflated || !LooksLikeZlib(b.data() + start, end - start)) {
            continue;
        }

        if (out.empty()) out.resize(kMaxStreamOutput);
        z_stream zs = {};
        if (inflateInit(&zs) != Z_OK) continue;
        zs.next_in = const_cast<Bytef*>(b.data() + start);
        zs.avail_in = (uInt)(end - start);
        size_t budget = std::min(kMaxStreamOutput, kMaxTotalInflated - c.inflated_bytes);
        zs.next_out = out.data();
        zs.avail_out = (uInt)budget;
        inflate(&zs, Z_SYNC_FLUSH);
        size_t produced = budget - zs.avail_out;
        inflateEnd(&zs);
        if (produced == 0) continue;
        c.inflated_streams++;
        c.inflated_bytes += produced;
        CountNames(out.data(), produced, c);
        if (!c.signature) c.signature = FindKnownBadSignature(out.data(), produced);
    }
}

size_t FindLast(const std::vector<uint8_t>& b, const char* needle, size_t len, size_t limit) {
    if (limit < len) return SIZE_MAX;
    for (size_t i = limit - len + 1; i-- > 0;) {
        if (memcmp(b.data() + i, needle, len) == 0) return i;
    }
    return SIZE_MAX;
}

bool IsPdfWhitespace(uint8_t c) {
    return c == 0 || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' ';
}

bool IsObjectHeader(const std::vector<uint8_t>& b, size_t i) {
    for (int field = 0; field < 2; field++) {
        size_t digits = 0;
        while (i < b.size() && isdigit(b[i]) && digits < 10) {
            i++;
            digits++;
        }
        if (digits == 0 || i >= b.size() || !IsPdfWhitespace(b[i])) return false;
        while (i < b.size() && IsPdfWhitespace(b[i])) i++;
    }
    return b.size() - i >= 3 && memcmp(b.data() + i, "obj", 3) == 0;
}

}  // namespace

CheapFilterResult ScanPdf(const std::vector<uint8_t>& b, std::string& out_json) {
    CheapFilterResult r;
    auto flag = [&](const std::string& reason) {
        if (!r.flagged) {
            r.flagged = true;
            r.reason = reason;
        }
    };

    size_t window = std::min(b.size(), kHeaderWindow);
    const void* hdr = window >= 5 ? memmem(b.data(), window, "%PDF-", 5) : nullptr;
    size_t header_off = hdr ? (size_t)((const uint8_t*)hdr - b.data()) : 0;
    std::string version;
    for (size_t i = header_off + 5; hdr && i < b.size() && i < header_off + 9; i++) {
        if (!(isdigit(b[i]) || b[i] == '.')) break;
        version += (char)b[i];
    }

    Counts c;
    c.signature = FindKnownBadSignature(b.data(), b.size());
    CountNames(b.data(), b.size(), c);
    InflateStreams(b, c);

    size_t eof = FindLast(b, "%%EOF", 5, b.size());
    bool startxref_valid = false;
    size_t trailing = 0;
    if (eof != SIZE_MAX) {
        for (size_t i = eof + 5; i < b.size(); i++) {
            if (!IsPdfWhitespace(b[i])) trailing++;
        }
        size_t sx = FindLast(b, "startxref", 9, eof);
        if (sx != SIZE_MAX) {
            size_t i = sx + 9;
            while (i < eof && IsPdfWhitespace(b[i])) i++;
            uint64_t off = 0;
            size_t digits = 0;
            while (i < eof && isdigit(b[i]) && digits < 20) {
                off = off * 10 + (b[i++] - '0');
                digits++;
            }
            if (digits > 0 && off < b.size()) {
                size_t o = (size_t)off;
                startxref_valid = (b.size() - o >= 4 && memcmp(b.data() + o, "xref", 4) == 0) ||
                                  IsObjectHeader(b, o);
            } else if (digits > 0) {
                flag("PDF startxref points past the end of the file");
            }
        }
    }

    if (c.signature) flag(std::string("contains ") + c.signature);
    if (header_off > 0) flag(std::to_string(header_off) + " bytes of data before the %PDF- header");
    if (eof == SIZE_MAX) flag("PDF has no %%EOF marker");
    if (trailing > kMaxTrailingBytes) {
        flag(std::to_string(trailing) + " bytes of data after the final %%EOF");
    }
    if (c.obfuscated > 0) flag("hex-obfuscated PDF name /" + c.first_obfuscated);
    bool auto_action = c.keywords[kOpenAction] > 0 || c.keywords[kAa] > 0;
    bool js = c.keywords[kJs] > 0 || c.keywords[kJavaScript] > 0;
    if (js && auto_action) flag("PDF runs JavaScript automatically (OpenAction/AA)");
    if (c.keywords[kLaunch] > 0) flag("PDF contains a /Launch action");

    out_json = "{\"file_type\":\"pdf\",\"pdf_version\":\"" + JsonEscape(version) +
               "\",\"pdf_header_offset\":" + std::to_string(header_off) +
               ",\"pdf_streams\":" + std::to_string(c.streams) +
               ",\"pdf_inflated_streams\":" + std::to_string(c.inflated_streams) +
               ",\"pdf_startxref_valid\":" + (startxref_valid ? "true" : "false") +
               ",\"pdf_trailing_bytes\":" + std::to_string(trailing) +
               ",\"pdf_obfuscated_names\":" + std::to_string(c.obfuscated);
    for (int k = 0; k < kKeywordCount; k++) {
        out_json += std::string(",\"") + kKeywordJsonKeys[k] + "\":" + std::to_string(c.keywords[k]);
    }
    out_json += "}";
    return r;
}

}  // namespace noxos
