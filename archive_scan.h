#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "cheap_filter_types.h"

namespace noxos {

bool LooksLikeTar(const uint8_t* p, size_t n);

CheapFilterResult ScanArchive(const std::vector<uint8_t>& file_bytes, const std::string& type,
                              std::string& out_json);

}  // namespace noxos
