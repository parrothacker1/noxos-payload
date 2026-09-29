#include "../file_scan.h"

#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<uint8_t> payload(data, data + size);
    std::string name;
    std::string mime;
    if (noxos::StripFileScanMeta(payload, name, mime)) {
        noxos::ScanFile(payload, &name, &mime);
    } else {
        noxos::ScanFile(payload, nullptr, nullptr);
    }
    return 0;
}
