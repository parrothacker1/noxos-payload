#include "../zip_scan.h"

#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<uint8_t> file_bytes(data, data + size);
    std::string json;
    if (noxos::LooksLikeZip(file_bytes)) noxos::ScanZip(file_bytes, json);
    return 0;
}
