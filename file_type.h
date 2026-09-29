#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "cheap_filter_types.h"

namespace noxos {

const char* DetectFileType(const std::vector<uint8_t>& file_bytes);

CheapFilterResult CheckDeclaredType(const std::string& name, const std::string& mime,
                                    const std::string& actual_type);

}  // namespace noxos
