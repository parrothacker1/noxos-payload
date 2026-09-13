#include "file_cheap_filter.h"

#include <cstring>

namespace noxos {
namespace {

constexpr size_t kMinScanDataBytes = 32;
constexpr size_t kMaxBenignTrailerBytes = 4096;

uint16_t ReadU16Be(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

struct MagicSig {
    const char* bytes;
    size_t len;
    const char* name;
};

const MagicSig kForeignMagics[] = {
    {"PK\x03\x04", 4, "ZIP local file header"},
    {"\x1F\x8B", 2, "gzip"},
    {"\x7F""ELF", 4, "ELF executable"},
    {"MZ", 2, "Windows PE/DOS executable"},
    {"%PDF-", 5, "PDF"},
    {"#!", 2, "shebang script"},
    {"<?php", 5, "PHP script"},
    {"<script", 7, "HTML script tag"},
};

bool FindForeignMagic(const std::vector<uint8_t>& b, size_t start, size_t end,
                       std::string& out_name, size_t& out_offset) {
    for (size_t i = start; i < end; i++) {
        for (const auto& sig : kForeignMagics) {
            if (i + sig.len <= end &&
                memcmp(b.data() + i, sig.bytes, sig.len) == 0) {
                out_name = sig.name;
                out_offset = i;
                return true;
            }
        }
    }
    return false;
}

bool FindScanDataStart(const std::vector<uint8_t>& b, size_t* scan_start) {
    size_t pos = 2;
    size_t size = b.size();

    while (pos + 4 <= size) {
        if (b[pos] != 0xFF) return false;

        uint8_t marker = b[pos + 1];
        if (marker == 0xD9) return false;

        uint16_t seg_len = ReadU16Be(b.data() + pos + 2);
        if (seg_len < 2) return false;

        if (marker == 0xDA) {
            size_t start = pos + 2 + (size_t)seg_len;
            if (start > size) return false;
            *scan_start = start;
            return true;
        }

        if (pos + 2 + (size_t)seg_len > size) return false;
        pos += 2 + seg_len;
    }
    return false;
}

bool FindLastEoi(const std::vector<uint8_t>& b, size_t start, size_t* eoi_pos) {
    if (b.size() < 2 || start > b.size() - 2) return false;
    for (ptrdiff_t i = (ptrdiff_t)(b.size() - 2); i >= (ptrdiff_t)start; i--) {
        if (b[(size_t)i] == 0xFF && b[(size_t)i + 1] == 0xD9) {
            *eoi_pos = (size_t)i;
            return true;
        }
    }
    return false;
}

}  // namespace

CheapFilterResult CheckFileCheapFilter(const std::vector<uint8_t>& file_bytes) {
    CheapFilterResult result;

    size_t scan_start;
    if (!FindScanDataStart(file_bytes, &scan_start)) {
        result.flagged = true;
        result.reason = "no JPEG scan data (SOS marker) found before EOI or end of file";
        return result;
    }

    size_t remaining = file_bytes.size() - scan_start;
    if (remaining < kMinScanDataBytes) {
        result.flagged = true;
        result.reason = "insufficient image scan data (" + std::to_string(remaining) +
                         " bytes) for a real photo";
        return result;
    }

    size_t eoi_pos;
    if (FindLastEoi(file_bytes, scan_start, &eoi_pos)) {
        size_t trailer_start = eoi_pos + 2;
        size_t trailing = file_bytes.size() - trailer_start;
        if (trailing > 0) {
            std::string magic_name;
            size_t magic_offset;
            if (FindForeignMagic(file_bytes, trailer_start, file_bytes.size(),
                                  magic_name, magic_offset)) {
                result.flagged = true;
                result.reason = "embedded " + magic_name + " signature " +
                                 std::to_string(magic_offset - trailer_start) +
                                 " bytes after JPEG EOI marker";
                return result;
            }
            if (trailing > kMaxBenignTrailerBytes) {
                result.flagged = true;
                result.reason = std::to_string(trailing) +
                                 " bytes of unexplained trailing data after JPEG EOI marker";
                return result;
            }
        }
    }

    return result;
}

}  // namespace noxos
