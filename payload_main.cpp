#include "exif_parser.h"
#include "file_cheap_filter.h"
#include "json_util.h"
#include "network_cheap_filter.h"

#include <vm_main.h>
#include <vm_payload.h>

#include <errno.h>
#include <linux/vm_sockets.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <vector>

static constexpr uint32_t VSOCK_PORT = 5000;
static constexpr size_t MAX_PAYLOAD_BYTES = 10 * 1024 * 1024;
static constexpr uint8_t TASK_FILE_SCAN = 0;
static constexpr uint8_t TASK_NETWORK_SAMPLE = 1;

static uint32_t read_u32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static bool read_exact(int fd, uint8_t* buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, buf + done, n - done);
        if (r <= 0) return false;
        done += (size_t)r;
    }
    return true;
}

static bool write_exact(int fd, const uint8_t* buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, buf + done, n - done);
        if (w <= 0) return false;
        done += (size_t)w;
    }
    return true;
}

static void send_response(int fd, uint8_t status, const std::string& json) {
    uint32_t json_len = (uint32_t)json.size();
    uint32_t payload_len = 1 + json_len;

    uint8_t hdr[4];
    hdr[0] = (payload_len >> 24) & 0xFF;
    hdr[1] = (payload_len >> 16) & 0xFF;
    hdr[2] = (payload_len >>  8) & 0xFF;
    hdr[3] = (payload_len      ) & 0xFF;

    write_exact(fd, hdr, 4);
    write_exact(fd, &status, 1);
    write_exact(fd, reinterpret_cast<const uint8_t*>(json.data()), json_len);
}

static void handle_file_scan(int client_fd, const std::vector<uint8_t>& payload) {
    if (payload.empty()) {
        send_response(client_fd, noxos::kStatusMalformedInput,
                       "{\"error\":\"file size out of range\"}");
        return;
    }

    std::string result_json;
    uint8_t status = (uint8_t)noxos::ParseExif(payload, result_json);

    if (status == noxos::kStatusOk) {
        noxos::CheapFilterResult cheap = noxos::CheckFileCheapFilter(payload);
        if (cheap.flagged) {
            result_json.pop_back();
            result_json += ",\"cheap_filter_flagged\":true,\"cheap_filter_reason\":\"" +
                            noxos::JsonEscape(cheap.reason) + "\"}";
        }
    }

    send_response(client_fd, status, result_json);
}

static void handle_network_sample(int client_fd, const std::vector<uint8_t>& payload) {
    std::vector<std::vector<uint8_t>> packets;
    if (!noxos::DecodePacketSamples(payload, &packets)) {
        send_response(client_fd, noxos::kStatusMalformedInput,
                       "{\"error\":\"malformed packet sample framing\"}");
        return;
    }

    noxos::CheapFilterResult cheap = noxos::CheckNetworkCheapFilter(packets);
    std::string result_json = cheap.flagged
        ? "{\"flagged\":true,\"reason\":\"" + noxos::JsonEscape(cheap.reason) + "\"}"
        : "{\"flagged\":false}";

    send_response(client_fd, noxos::kStatusOk, result_json);
}

static void handle_connection(int client_fd) {
    uint8_t task_type;
    if (!read_exact(client_fd, &task_type, 1)) {
        printf("noxos-payload: failed to read task-type byte\n");
        return;
    }

    uint8_t len_buf[4];
    if (!read_exact(client_fd, len_buf, 4)) {
        printf("noxos-payload: failed to read length prefix\n");
        return;
    }
    uint32_t payload_len = read_u32_be(len_buf);

    if (payload_len > MAX_PAYLOAD_BYTES) {
        send_response(client_fd, noxos::kStatusMalformedInput,
                       "{\"error\":\"payload size out of range\"}");
        return;
    }

    std::vector<uint8_t> payload(payload_len);
    if (payload_len > 0 && !read_exact(client_fd, payload.data(), payload_len)) {
        send_response(client_fd, noxos::kStatusMalformedInput,
                       "{\"error\":\"incomplete payload received\"}");
        return;
    }

    switch (task_type) {
        case TASK_FILE_SCAN:
            handle_file_scan(client_fd, payload);
            break;
        case TASK_NETWORK_SAMPLE:
            handle_network_sample(client_fd, payload);
            break;
        default:
            send_response(client_fd, noxos::kStatusMalformedInput,
                           "{\"error\":\"unknown task type\"}");
            break;
    }
}

extern "C" int AVmPayload_main() {
    setvbuf(stdin, nullptr, _IONBF, 0);
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    printf("noxos-payload: AVmPayload_main entered\n");
    printf("noxos-payload: starting EXIF parser on vsock port %u\n", VSOCK_PORT);

    int server_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (server_fd < 0) {
        printf("noxos-payload: socket() failed: %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_vm addr = {};
    addr.svm_family = AF_VSOCK;
    addr.svm_cid    = VMADDR_CID_ANY;
    addr.svm_port   = VSOCK_PORT;

    if (bind(server_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        printf("noxos-payload: bind() failed: %s\n", strerror(errno));
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        printf("noxos-payload: listen() failed: %s\n", strerror(errno));
        close(server_fd);
        return 1;
    }

    printf("noxos-payload: listening for scan requests\n");

    AVmPayload_notifyPayloadReady();

    struct sockaddr_vm client_addr = {};
    socklen_t addr_len = sizeof(client_addr);
    int client_fd = accept(server_fd,
                           reinterpret_cast<struct sockaddr*>(&client_addr),
                           &addr_len);
    if (client_fd < 0) {
        printf("noxos-payload: accept() failed: %s\n", strerror(errno));
        close(server_fd);
        return 1;
    }

    printf("noxos-payload: connection accepted, scanning\n");
    handle_connection(client_fd);
    close(client_fd);
    close(server_fd);

    printf("noxos-payload: scan complete, exiting\n");
    return 0;
}
