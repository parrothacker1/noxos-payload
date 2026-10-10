#pragma once

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace noxos {

inline double ShannonEntropy(const uint8_t* p, size_t n) {
    if (n == 0) return 0.0;
    size_t counts[256] = {};
    for (size_t i = 0; i < n; i++) counts[p[i]]++;
    double h = 0.0;
    for (size_t c : counts) {
        if (c == 0) continue;
        double f = (double)c / (double)n;
        h -= f * std::log2(f);
    }
    return h;
}

inline bool ContainsBytes(const uint8_t* p, size_t n, const char* needle, size_t len) {
    return len > 0 && n >= len && memmem(p, n, needle, len) != nullptr;
}

constexpr uint8_t kSignatureMask = 0x5A;

constexpr uint8_t kMaskedSig0[] = {0x02, 0x6F, 0x15, 0x7B, 0x0A, 0x7F, 0x1A, 0x1B, 0x0A, 0x01, 0x6E, 0x06, 0x0A, 0x00, 0x02, 0x6F, 0x6E, 0x72, 0x0A, 0x04, 0x73, 0x6D, 0x19, 0x19, 0x73, 0x6D, 0x27, 0x7E, 0x1F, 0x13, 0x19, 0x1B, 0x08, 0x77, 0x09, 0x0E, 0x1B, 0x14, 0x1E, 0x1B, 0x08, 0x1E, 0x77, 0x1B, 0x14, 0x0E, 0x13, 0x0C, 0x13, 0x08, 0x0F, 0x09, 0x77, 0x0E, 0x1F, 0x09, 0x0E, 0x77, 0x1C, 0x13, 0x16, 0x1F, 0x7B, 0x7E, 0x12, 0x71, 0x12, 0x70};
constexpr uint8_t kMaskedSig1[] = {0x16, 0x39, 0x35, 0x37, 0x75, 0x37, 0x3F, 0x2E, 0x3B, 0x29, 0x2A, 0x36, 0x35, 0x33, 0x2E, 0x75, 0x29, 0x2E, 0x3B, 0x3D, 0x3F, 0x75};
constexpr uint8_t kMaskedSig2[] = {0x39, 0x35, 0x37, 0x74, 0x37, 0x3F, 0x2E, 0x3B, 0x29, 0x2A, 0x36, 0x35, 0x33, 0x2E, 0x74, 0x29, 0x2E, 0x3B, 0x3D, 0x3F};
constexpr uint8_t kMaskedSig3[] = {0x37, 0x3F, 0x2E, 0x3B, 0x29, 0x2A, 0x36, 0x35, 0x33, 0x2E, 0x74, 0x3E, 0x3B, 0x2E};

struct MaskedSignature {
    const uint8_t* bytes;
    size_t len;
    const char* name;
};

inline const MaskedSignature kKnownBadSignatures[] = {
    {kMaskedSig0, sizeof(kMaskedSig0), "EICAR antivirus test string"},
    {kMaskedSig1, sizeof(kMaskedSig1), "Metasploit Android stager class"},
    {kMaskedSig2, sizeof(kMaskedSig2), "Metasploit Android stager package"},
    {kMaskedSig3, sizeof(kMaskedSig3), "Metasploit stager config"},
};

inline const char* FindKnownBadSignature(const uint8_t* p, size_t n) {
    for (const auto& sig : kKnownBadSignatures) {
        if (n < sig.len) continue;
        std::string needle(sig.len, '\0');
        for (size_t i = 0; i < sig.len; i++) needle[i] = (char)(sig.bytes[i] ^ kSignatureMask);
        if (ContainsBytes(p, n, needle.data(), needle.size())) return sig.name;
    }
    return nullptr;
}

struct ForeignMagic {
    const char* bytes;
    size_t len;
    const char* name;
    bool only_at_start;
};

inline const ForeignMagic kForeignMagics[] = {
    {"PK\x03\x04", 4, "ZIP local file header", false},
    {"\x1F\x8B\x08", 3, "gzip", false},
    {"\x7F""ELF", 4, "ELF executable", false},
    {"MZ", 2, "Windows PE/DOS executable", true},
    {"%PDF-", 5, "PDF", false},
    {"#!", 2, "shebang script", true},
    {"<?php", 5, "PHP script", false},
    {"<script", 7, "HTML script tag", false},
    {"dex\n0", 5, "DEX file", false},
    {"Rar!\x1A\x07", 6, "RAR archive", false},
    {"7z\xBC\xAF\x27\x1C", 6, "7z archive", false},
};

inline const char* FindForeignMagic(const std::vector<uint8_t>& b, size_t start) {
    for (size_t i = start; i < b.size(); i++) {
        for (const auto& sig : kForeignMagics) {
            if (sig.only_at_start && i != start) continue;
            if (b.size() - i >= sig.len && memcmp(b.data() + i, sig.bytes, sig.len) == 0) {
                return sig.name;
            }
        }
    }
    return nullptr;
}

inline uint16_t ReadU16Le(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

inline uint32_t ReadU32Le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

inline uint64_t ReadU64Le(const uint8_t* p) {
    return (uint64_t)ReadU32Le(p) | ((uint64_t)ReadU32Le(p + 4) << 32);
}

}  // namespace noxos
