#include "../network_cheap_filter.h"

#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<uint8_t> payload(data, data + size);
    std::vector<std::vector<uint8_t>> packets;
    if (noxos::DecodePacketSamples(payload, &packets)) {
        noxos::CheckNetworkCheapFilter(packets);
    }
    return 0;
}
