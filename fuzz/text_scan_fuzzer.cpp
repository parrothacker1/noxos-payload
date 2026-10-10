#include "../text_scan.h"

#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    static const char* const kTypes[] = {"html", "svg", "script"};
    std::vector<uint8_t> file_bytes(data + 1, data + size);
    std::string json;
    noxos::ScanText(file_bytes, kTypes[data[0] % 3], json);
    noxos::LooksLikeSvg(file_bytes);
    noxos::LooksLikeHtml(file_bytes);
    return 0;
}
