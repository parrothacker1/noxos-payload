#include "../network_cheap_filter.h"

#include <cassert>
#include <cstdio>
#include <vector>

namespace {

void PushBe16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back((x >> 8) & 0xFF);
    v.push_back(x & 0xFF);
}

void PushBe32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back((x >> 24) & 0xFF);
    v.push_back((x >> 16) & 0xFF);
    v.push_back((x >> 8) & 0xFF);
    v.push_back(x & 0xFF);
}

uint16_t ComputeIpv4HeaderChecksumForTest(const std::vector<uint8_t>& header) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < header.size(); i += 2) {
        uint16_t word = (i == 10) ? 0 : (uint16_t)((header[i] << 8) | header[i + 1]);
        sum += word;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

std::vector<uint8_t> BuildValidIpv4UdpPacket(const std::vector<uint8_t>& udp_payload) {
    uint16_t total_len = (uint16_t)(20 + 8 + udp_payload.size());
    uint16_t udp_len = (uint16_t)(8 + udp_payload.size());

    std::vector<uint8_t> ip;
    ip.push_back(0x45);
    ip.push_back(0x00);
    PushBe16(ip, total_len);
    PushBe16(ip, 0);
    PushBe16(ip, 0);
    ip.push_back(64);
    ip.push_back(17);
    PushBe16(ip, 0);
    ip.push_back(10); ip.push_back(0); ip.push_back(0); ip.push_back(1);
    ip.push_back(10); ip.push_back(0); ip.push_back(0); ip.push_back(2);

    uint16_t checksum = ComputeIpv4HeaderChecksumForTest(ip);
    ip[10] = (checksum >> 8) & 0xFF;
    ip[11] = checksum & 0xFF;

    PushBe16(ip, 5555);
    PushBe16(ip, 53);
    PushBe16(ip, udp_len);
    PushBe16(ip, 0);
    ip.insert(ip.end(), udp_payload.begin(), udp_payload.end());

    return ip;
}

std::vector<uint8_t> EncodeSamples(const std::vector<std::vector<uint8_t>>& samples) {
    std::vector<uint8_t> out;
    PushBe16(out, (uint16_t)samples.size());
    for (const auto& s : samples) {
        PushBe32(out, (uint32_t)s.size());
        out.insert(out.end(), s.begin(), s.end());
    }
    return out;
}

}  // namespace

int main() {
    {
        auto pkt = BuildValidIpv4UdpPacket({'t', 'e', 's', 't'});
        auto payload = EncodeSamples({pkt});
        std::vector<std::vector<uint8_t>> packets;
        assert(noxos::DecodePacketSamples(payload, &packets));
        assert(packets.size() == 1);
        assert(packets[0] == pkt);
    }

    {
        std::vector<uint8_t> truncated = {0x00, 0x01, 0x00, 0x00, 0x00, 0x10};
        std::vector<std::vector<uint8_t>> packets;
        assert(!noxos::DecodePacketSamples(truncated, &packets));
    }

    {
        auto pkt = BuildValidIpv4UdpPacket({'x'});
        auto payload = EncodeSamples({pkt});
        payload.push_back(0xFF);
        std::vector<std::vector<uint8_t>> packets;
        assert(!noxos::DecodePacketSamples(payload, &packets));
    }

    {
        auto pkt = BuildValidIpv4UdpPacket({'t', 'e', 's', 't'});
        noxos::CheapFilterResult r = noxos::CheckNetworkCheapFilter({pkt});
        assert(!r.flagged);
    }

    {
        std::vector<uint8_t> tiny = {0x45, 0x00, 0x00, 0x14};
        noxos::CheapFilterResult r = noxos::CheckNetworkCheapFilter({tiny});
        assert(r.flagged);
        assert(r.reason.find("too short") != std::string::npos);
    }

    {
        auto pkt = BuildValidIpv4UdpPacket({'t', 'e', 's', 't'});
        pkt[0] = 0x65;
        noxos::CheapFilterResult r = noxos::CheckNetworkCheapFilter({pkt});
        assert(r.flagged);
        assert(r.reason.find("IP version") != std::string::npos);
    }

    {
        auto pkt = BuildValidIpv4UdpPacket({'t', 'e', 's', 't'});
        pkt[0] = 0x43;
        noxos::CheapFilterResult r = noxos::CheckNetworkCheapFilter({pkt});
        assert(r.flagged);
    }

    {
        auto pkt = BuildValidIpv4UdpPacket({'t', 'e', 's', 't'});
        pkt[2] = 0x00;
        pkt[3] = 0x05;
        noxos::CheapFilterResult r = noxos::CheckNetworkCheapFilter({pkt});
        assert(r.flagged);
        assert(r.reason.find("total-length") != std::string::npos);
    }

    {
        auto pkt = BuildValidIpv4UdpPacket({'t', 'e', 's', 't'});
        pkt[8] = 0;
        noxos::CheapFilterResult r = noxos::CheckNetworkCheapFilter({pkt});
        assert(r.flagged);
        assert(r.reason.find("TTL") != std::string::npos);
    }

    {
        auto pkt = BuildValidIpv4UdpPacket({'t', 'e', 's', 't'});
        pkt[9] = 253;
        noxos::CheapFilterResult r = noxos::CheckNetworkCheapFilter({pkt});
        assert(r.flagged);
        assert(r.reason.find("unrecognized IP protocol") != std::string::npos);
    }

    {
        auto pkt = BuildValidIpv4UdpPacket({'t', 'e', 's', 't'});
        pkt[10] ^= 0xFF;
        noxos::CheapFilterResult r = noxos::CheckNetworkCheapFilter({pkt});
        assert(r.flagged);
        assert(r.reason.find("checksum") != std::string::npos);
    }

    {
        auto pkt = BuildValidIpv4UdpPacket({'t', 'e', 's', 't'});
        std::vector<uint8_t> huge_reply(70000, 0x41);
        noxos::CheapFilterResult r = noxos::CheckNetworkCheapFilter({pkt, huge_reply});
        assert(r.flagged);
        assert(r.reason.find("implausibly large") != std::string::npos);
    }

    {
        auto pkt = BuildValidIpv4UdpPacket({'t', 'e', 's', 't'});
        std::vector<uint8_t> normal_reply = {'o', 'k'};
        noxos::CheapFilterResult r = noxos::CheckNetworkCheapFilter({pkt, normal_reply});
        assert(!r.flagged);
    }

    {
        noxos::CheapFilterResult r = noxos::CheckNetworkCheapFilter({});
        assert(r.flagged);
    }

    printf("ok: network_cheap_filter_test passed\n");
    return 0;
}
