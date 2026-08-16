#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace noxos {

constexpr uint8_t kStatusOk = 0;
constexpr uint8_t kStatusParseError = 1;
constexpr uint8_t kStatusMalformedInput = 2;

int ParseExif(const std::vector<uint8_t>& file_bytes, std::string& out_json);

}  // namespace noxos
