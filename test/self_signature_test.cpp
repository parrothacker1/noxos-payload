#include "../scan_util.h"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <vector>

int main() {
    std::ifstream f("/proc/self/exe", std::ios::binary);
    std::vector<uint8_t> self((std::istreambuf_iterator<char>(f)), {});
    assert(self.size() > 1000);
    assert(noxos::FindKnownBadSignature(self.data(), self.size()) == nullptr);

    std::vector<uint8_t> sample;
    for (uint8_t m : noxos::kMaskedSig0) sample.push_back(m ^ noxos::kSignatureMask);
    assert(noxos::FindKnownBadSignature(sample.data(), sample.size()) != nullptr);
    sample.assign({'x'});
    assert(noxos::FindKnownBadSignature(sample.data(), sample.size()) == nullptr);
    assert(noxos::FindKnownBadSignature(nullptr, 0) == nullptr);

    printf("ok: self_signature_test passed\n");
    return 0;
}
