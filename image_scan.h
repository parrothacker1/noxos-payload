#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "cheap_filter_types.h"

namespace noxos {

CheapFilterResult ScanImage(const std::vector<uint8_t>& file_bytes, const std::string& type,
                            std::string& out_json);

}  // namespace noxos
