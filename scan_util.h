#pragma once

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

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

struct ByteSignature {
    const char* bytes;
    size_t len;
    const char* name;
};

inline const ByteSignature kKnownBadSignatures[] = {
    {"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", 68,
     "EICAR antivirus test string"},
    {"Lcom/metasploit/stage/", 22, "Metasploit Android stager class"},
    {"com.metasploit.stage", 20, "Metasploit Android stager package"},
    {"metasploit.dat", 14, "Metasploit stager config"},
};

inline const char* FindKnownBadSignature(const uint8_t* p, size_t n) {
    for (const auto& sig : kKnownBadSignatures) {
        if (ContainsBytes(p, n, sig.bytes, sig.len)) return sig.name;
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
