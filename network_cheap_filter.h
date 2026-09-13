#pragma once

#include <cstdint>
#include <vector>

#include "cheap_filter_types.h"

namespace noxos {

bool DecodePacketSamples(const std::vector<uint8_t>& payload,
                          std::vector<std::vector<uint8_t>>* out_packets);

CheapFilterResult CheckNetworkCheapFilter(
    const std::vector<std::vector<uint8_t>>& packets);

}  // namespace noxos
