#include "../file_cheap_filter.h"

#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<uint8_t> file_bytes(data, data + size);
    noxos::CheckFileCheapFilter(file_bytes);
    return 0;
}
