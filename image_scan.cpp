#include "image_scan.h"

#include <zlib.h>

#include <algorithm>
#include <cstring>

#include "scan_util.h"

namespace noxos {
namespace {

constexpr size_t kMaxBenignTrailerBytes = 4096;
constexpr uint64_t kMaxPixels = 1ull << 28;

struct Info {
    uint32_t width = 0;
    uint32_t height = 0;
    size_t chunks = 0;
    size_t crc_errors = 0;
    size_t trailing = 0;
    bool ended = false;
    bool structure_ok = true;
    std::string first_problem;
};

uint32_t ReadU32Be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

void Problem(Info& info, std::string reason) {
    info.structure_ok = false;
    if (info.first_problem.empty()) info.first_problem = std::move(reason);
}

void WalkPng(const std::vector<uint8_t>& b, Info& info) {
    size_t pos = 8;
    bool first = true;
    while (pos + 12 <= b.size()) {
        uint32_t len = ReadU32Be(b.data() + pos);
        const uint8_t* type = b.data() + pos + 4;
        if (len > 0x7FFFFFFF || b.size() - pos - 12 < len) {
            Problem(info, "PNG chunk " + std::string(reinterpret_cast<const char*>(type), 4) +
                              " declares " + std::to_string(len) + " bytes but the file ends first");
            return;
        }
        for (int i = 0; i < 4; i++) {
            if (!isalpha(type[i])) {
                Problem(info, "PNG chunk has a non-letter type byte");
                return;
            }
        }
        if (first) {
            if (memcmp(type, "IHDR", 4) != 0 || len != 13) {
                Problem(info, "PNG does not start with a valid IHDR chunk");
                return;
            }
            info.width = ReadU32Be(b.data() + pos + 8);
            info.height = ReadU32Be(b.data() + pos + 12);
            first = false;
        }
        uLong crc = crc32(0L, type, 4 + len);
        if ((uint32_t)crc != ReadU32Be(b.data() + pos + 8 + len)) info.crc_errors++;
        info.chunks++;
        pos += 12 + (size_t)len;
        if (memcmp(type, "IEND", 4) == 0) {
            info.ended = true;
            info.trailing = b.size() - pos;
            return;
        }
    }
    Problem(info, "PNG has no IEND chunk");
}

void SkipSubBlocks(const std::vector<uint8_t>& b, size_t& pos, bool& ok) {
    while (true) {
        if (pos >= b.size()) {
            ok = false;
            return;
        }
        size_t n = b[pos++];
        if (n == 0) return;
        if (b.size() - pos < n) {
            ok = false;
            return;
        }
        pos += n;
    }
}

void WalkGif(const std::vector<uint8_t>& b, Info& info) {
    if (b.size() < 13) {
        Problem(info, "GIF is shorter than its logical screen descriptor");
        return;
    }
    info.width = ReadU16Le(b.data() + 6);
    info.height = ReadU16Le(b.data() + 8);
    size_t pos = 13;
    if (b[10] & 0x80) pos += (size_t)3 << ((b[10] & 7) + 1);
    while (pos < b.size()) {
        uint8_t block = b[pos++];
        if (block == 0x3B) {
            info.ended = true;
            info.trailing = b.size() - pos;
            return;
        }
        bool ok = true;
        if (block == 0x21) {
            if (pos >= b.size()) ok = false;
            else {
                pos++;
                SkipSubBlocks(b, pos, ok);
            }
        } else if (block == 0x2C) {
            if (b.size() - pos < 10) {
                ok = false;
            } else {
                uint8_t flags = b[pos + 8];
                pos += 9;
                if (flags & 0x80) pos += (size_t)3 << ((flags & 7) + 1);
                pos++;
                if (pos > b.size()) ok = false;
                else SkipSubBlocks(b, pos, ok);
            }
            info.chunks++;
        } else {
            Problem(info, "GIF has an unknown block type 0x" + std::to_string(block));
            return;
        }
        if (!ok) {
            Problem(info, "GIF block runs past the end of the file");
            return;
        }
    }
    Problem(info, "GIF has no trailer byte");
}

void WalkWebp(const std::vector<uint8_t>& b, Info& info) {
    if (b.size() < 20) {
        Problem(info, "WebP is shorter than a RIFF header plus one chunk");
        return;
    }
    uint64_t riff_total = (uint64_t)ReadU32Le(b.data() + 4) + 8;
    if (riff_total > b.size()) {
        Problem(info, "WebP RIFF header declares " + std::to_string(riff_total) +
                          " bytes but the file is " + std::to_string(b.size()));
        return;
    }
    size_t end = (size_t)riff_total;
    info.trailing = b.size() - end;
    size_t pos = 12;
    while (pos + 8 <= end) {
        uint64_t len = ReadU32Le(b.data() + pos + 4);
        uint64_t padded = len + (len & 1);
        if (padded > end - pos - 8) {
            Problem(info, "WebP chunk " + std::string(reinterpret_cast<const char*>(b.data() + pos), 4) +
                              " runs past the RIFF size");
            return;
        }
        if (info.chunks == 0) {
            bool ok = memcmp(b.data() + pos, "VP8 ", 4) == 0 || memcmp(b.data() + pos, "VP8L", 4) == 0 ||
                      memcmp(b.data() + pos, "VP8X", 4) == 0;
            if (!ok) {
                Problem(info, "WebP does not start with a VP8/VP8L/VP8X chunk");
                return;
            }
            if (memcmp(b.data() + pos, "VP8X", 4) == 0 && len >= 10) {
                info.width = (ReadU32Le(b.data() + pos + 12) & 0xFFFFFF) + 1;
                info.height = (ReadU32Le(b.data() + pos + 15) & 0xFFFFFF) + 1;
            }
        }
        info.chunks++;
        pos += 8 + (size_t)padded;
    }
    if (pos != end) Problem(info, "WebP RIFF has stray bytes inside its declared size");
    info.ended = true;
}

}  // namespace

CheapFilterResult ScanImage(const std::vector<uint8_t>& b, const std::string& type,
                            std::string& out_json) {
    CheapFilterResult r;
    auto flag = [&](const std::string& reason) {
        if (!r.flagged) {
            r.flagged = true;
            r.reason = reason;
        }
    };

    Info info;
    if (type == "png") WalkPng(b, info);
    else if (type == "gif") WalkGif(b, info);
    else WalkWebp(b, info);

    if (const char* sig = FindKnownBadSignature(b.data(), b.size())) {
        flag(std::string("contains ") + sig);
    }
    if (!info.structure_ok) flag(info.first_problem);
    if (info.crc_errors > 0) flag(std::to_string(info.crc_errors) + " PNG chunk CRC mismatches");
    if (info.trailing > 0 && info.ended) {
        const char* magic = FindForeignMagic(b, b.size() - info.trailing);
        if (magic) {
            flag(std::string("embedded ") + magic + " signature right after the " + type +
                 " image data");
        } else if (info.trailing > kMaxBenignTrailerBytes) {
            flag(std::to_string(info.trailing) + " bytes of unexplained trailing data after the " +
                 type + " image data");
        }
    }
    if ((uint64_t)info.width * info.height > kMaxPixels) {
        flag("image declares " + std::to_string(info.width) + "x" + std::to_string(info.height) +
             " pixels");
    }

    out_json = "{\"file_type\":\"" + type + "\",\"image_width\":" + std::to_string(info.width) +
               ",\"image_height\":" + std::to_string(info.height) +
               ",\"image_chunks\":" + std::to_string(info.chunks) +
               ",\"image_trailing_bytes\":" + std::to_string(info.trailing) +
               ",\"image_crc_errors\":" + std::to_string(info.crc_errors) +
               ",\"image_structure_ok\":" + (info.structure_ok ? "true" : "false") + "}";
    return r;
}

}  // namespace noxos
