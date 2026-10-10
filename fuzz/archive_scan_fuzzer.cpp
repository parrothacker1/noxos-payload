#include "../archive_scan.h"

#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    static const char* const kTypes[] = {"gzip", "tar", "7z", "rar"};
    std::vector<uint8_t> file_bytes(data + 1, data + size);
    std::string json;
    noxos::ScanArchive(file_bytes, kTypes[data[0] % 4], json);
    return 0;
}
