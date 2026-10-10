#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "cheap_filter_types.h"

namespace noxos {

bool LooksLikeSvg(const std::vector<uint8_t>& file_bytes);

bool LooksLikeHtml(const std::vector<uint8_t>& file_bytes);

bool IsScriptExtension(const std::string& ext);

CheapFilterResult ScanText(const std::vector<uint8_t>& file_bytes, const std::string& type,
                           std::string& out_json);

}  // namespace noxos
