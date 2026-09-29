#include "../image_scan.h"

#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    static const char* const kTypes[] = {"png", "gif", "webp"};
    std::vector<uint8_t> file_bytes(data + 1, data + size);
    std::string json;
    noxos::ScanImage(file_bytes, kTypes[data[0] % 3], json);
    return 0;
}
