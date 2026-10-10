#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "cheap_filter_types.h"

namespace noxos {

CheapFilterResult ScanOle2(const std::vector<uint8_t>& file_bytes, std::string& out_json);

}  // namespace noxos
