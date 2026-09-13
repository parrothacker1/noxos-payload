#include "network_cheap_filter.h"

#include <string>

namespace noxos {
namespace {

constexpr size_t kMaxPacketBytes = 65535;
constexpr size_t kMaxReplyBytes = 65535;

uint16_t ReadU16Be(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

uint32_t ReadU32Be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint16_t ComputeIpv4HeaderChecksum(const uint8_t* header, size_t ihl) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < ihl; i += 2) {
        uint16_t word = (i == 10) ? 0 : ReadU16Be(header + i);
        sum += word;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

bool IsKnownIpProtocol(uint8_t proto) {
    switch (proto) {
        case 1:   // ICMP
        case 2:   // IGMP
        case 6:   // TCP
        case 17:  // UDP
        case 41:  // IPv6-in-IPv4
        case 47:  // GRE
        case 50:  // ESP
        case 51:  // AH
        case 58:  // ICMPv6
            return true;
        default:
            return false;
    }
}

CheapFilterResult CheckOutboundIpv4Packet(const std::vector<uint8_t>& ip) {
    CheapFilterResult result;

    if (ip.size() < 20) {
        result.flagged = true;
        result.reason = "outbound sample too short to be a valid IPv4 header";
        return result;
    }

    uint8_t version = ip[0] >> 4;
    size_t ihl = (size_t)(ip[0] & 0x0F) * 4;

    if (version != 4) {
        result.flagged = true;
        result.reason = "outbound sample has IP version " + std::to_string(version) +
                         ", expected 4";
        return result;
    }

    if (ihl < 20 || ihl > ip.size()) {
        result.flagged = true;
        result.reason = "IPv4 header length (IHL) out of bounds";
        return result;
    }

    uint16_t total_len = ReadU16Be(ip.data() + 2);
    if (total_len < ihl || total_len != ip.size()) {
        result.flagged = true;
        result.reason = "IPv4 total-length field (" + std::to_string(total_len) +
                         ") doesn't match captured packet size (" +
                         std::to_string(ip.size()) + ")";
        return result;
    }

    uint8_t ttl = ip[8];
    uint8_t proto = ip[9];

    if (ttl == 0) {
        result.flagged = true;
        result.reason = "IPv4 TTL is zero";
        return result;
    }

    if (!IsKnownIpProtocol(proto)) {
        result.flagged = true;
        result.reason = "unrecognized IP protocol number " + std::to_string(proto);
        return result;
    }

    uint16_t declared_checksum = ReadU16Be(ip.data() + 10);
    uint16_t computed_checksum = ComputeIpv4HeaderChecksum(ip.data(), ihl);
    if (declared_checksum != computed_checksum) {
        result.flagged = true;
        result.reason = "IPv4 header checksum mismatch";
        return result;
    }

    if (proto == 6) {
        if (ip.size() < ihl + 20) {
            result.flagged = true;
            result.reason = "TCP header truncated";
            return result;
        }
        size_t data_offset = (size_t)(ip[ihl + 12] >> 4) * 4;
        if (data_offset < 20 || ihl + data_offset > ip.size()) {
            result.flagged = true;
            result.reason = "TCP data offset out of bounds";
            return result;
        }
    } else if (proto == 17) {
        if (ip.size() < ihl + 8) {
            result.flagged = true;
            result.reason = "UDP header truncated";
            return result;
        }
        uint16_t udp_len = ReadU16Be(ip.data() + ihl + 4);
        if (udp_len < 8 || ihl + udp_len != ip.size()) {
            result.flagged = true;
            result.reason = "UDP length field (" + std::to_string(udp_len) +
                             ") doesn't match packet size";
            return result;
        }
    }

    return result;
}

CheapFilterResult CheckBarePayload(const std::vector<uint8_t>& payload) {
    CheapFilterResult result;
    if (payload.size() > kMaxReplyBytes) {
        result.flagged = true;
        result.reason = "inbound reply sample implausibly large (" +
                         std::to_string(payload.size()) + " bytes)";
    }
    return result;
}

}  // namespace

bool DecodePacketSamples(const std::vector<uint8_t>& payload,
                          std::vector<std::vector<uint8_t>>* out_packets) {
    if (payload.size() < 2) return false;

    uint16_t count = ReadU16Be(payload.data());
    size_t pos = 2;

    for (uint16_t i = 0; i < count; i++) {
        if (pos + 4 > payload.size()) return false;
        uint32_t len = ReadU32Be(payload.data() + pos);
        pos += 4;

        if (len > kMaxPacketBytes) return false;
        if (pos + len > payload.size()) return false;

        out_packets->emplace_back(payload.begin() + pos, payload.begin() + pos + len);
        pos += len;
    }

    return pos == payload.size();
}

CheapFilterResult CheckNetworkCheapFilter(
    const std::vector<std::vector<uint8_t>>& packets) {
    if (packets.empty()) {
        CheapFilterResult result;
        result.flagged = true;
        result.reason = "no packet samples provided";
        return result;
    }

    CheapFilterResult outbound = CheckOutboundIpv4Packet(packets[0]);
    if (outbound.flagged) return outbound;

    for (size_t i = 1; i < packets.size(); i++) {
        CheapFilterResult reply = CheckBarePayload(packets[i]);
        if (reply.flagged) return reply;
    }

    return CheapFilterResult{};
}

}  // namespace noxos
