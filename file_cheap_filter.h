#pragma once

#include <cstdint>
#include <vector>

#include "cheap_filter_types.h"

namespace noxos {

CheapFilterResult CheckFileCheapFilter(const std::vector<uint8_t>& file_bytes);

}  // namespace noxos
