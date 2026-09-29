#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace noxos {

constexpr size_t kMaxDeclaredNameBytes = 1024;
constexpr size_t kMaxDeclaredMimeBytes = 255;
constexpr size_t kMaxFileScanMetaBytes = 4 + kMaxDeclaredNameBytes + kMaxDeclaredMimeBytes;

struct FileScanOutput {
    uint8_t status;
    std::string json;
};

bool StripFileScanMeta(std::vector<uint8_t>& payload, std::string& name, std::string& mime);

FileScanOutput ScanFile(const std::vector<uint8_t>& file_bytes, const std::string* name,
                        const std::string* mime);

}  // namespace noxos
