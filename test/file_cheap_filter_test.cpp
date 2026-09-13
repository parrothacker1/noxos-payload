#include "../file_cheap_filter.h"

#include <cassert>
#include <cstdio>
#include <vector>

namespace {

void PushBe16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back((x >> 8) & 0xFF);
    v.push_back(x & 0xFF);
}

std::vector<uint8_t> BuildJpeg(size_t scan_data_len, bool with_eoi, bool with_sos) {
    std::vector<uint8_t> j = {0xFF, 0xD8};
    if (with_sos) {
        j.push_back(0xFF);
        j.push_back(0xDA);
        PushBe16(j, 4);
        j.push_back(0x00);
        j.push_back(0x00);
        for (size_t i = 0; i < scan_data_len; i++) {
            j.push_back((uint8_t)(0x10 + (i % 5)));
        }
    }
    if (with_eoi) {
        j.push_back(0xFF);
        j.push_back(0xD9);
    }
    return j;
}

}  // namespace

int main() {
    {
        auto jpeg = BuildJpeg(40, /*with_eoi=*/true, /*with_sos=*/true);
        noxos::CheapFilterResult r = noxos::CheckFileCheapFilter(jpeg);
        assert(!r.flagged);
    }

    {
        auto jpeg = BuildJpeg(0, /*with_eoi=*/true, /*with_sos=*/false);
        noxos::CheapFilterResult r = noxos::CheckFileCheapFilter(jpeg);
        assert(r.flagged);
        assert(r.reason.find("no JPEG scan data") != std::string::npos);
    }

    {
        auto jpeg = BuildJpeg(5, /*with_eoi=*/true, /*with_sos=*/true);
        noxos::CheapFilterResult r = noxos::CheckFileCheapFilter(jpeg);
        assert(r.flagged);
        assert(r.reason.find("insufficient image scan data") != std::string::npos);
    }

    {
        auto jpeg = BuildJpeg(40, /*with_eoi=*/true, /*with_sos=*/true);
        const uint8_t zip[] = {'P', 'K', 0x03, 0x04, 'x', 'x', 'x', 'x'};
        jpeg.insert(jpeg.end(), zip, zip + sizeof(zip));
        noxos::CheapFilterResult r = noxos::CheckFileCheapFilter(jpeg);
        assert(r.flagged);
        assert(r.reason.find("ZIP local file header") != std::string::npos);
    }

    {
        auto jpeg = BuildJpeg(40, /*with_eoi=*/false, /*with_sos=*/true);
        noxos::CheapFilterResult r = noxos::CheckFileCheapFilter(jpeg);
        assert(!r.flagged);
    }

    printf("ok: file_cheap_filter_test passed\n");
    return 0;
}
