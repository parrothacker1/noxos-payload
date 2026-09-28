#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "cheap_filter_types.h"

namespace noxos {

bool LooksLikeZip(const std::vector<uint8_t>& file_bytes);

CheapFilterResult ScanZip(const std::vector<uint8_t>& file_bytes, std::string& out_json);

}  // namespace noxos
