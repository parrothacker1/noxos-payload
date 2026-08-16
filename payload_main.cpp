#include "exif_parser.h"

#include <vm_payload/api.h>

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
static constexpr size_t MAX_FILE_BYTES = 10 * 1024 * 1024;

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

static void handle_scan(int client_fd) {
    uint8_t len_buf[4];
    if (!read_exact(client_fd, len_buf, 4)) {
        printf("noxos-payload: failed to read length prefix\n");
        return;
    }
    uint32_t file_len = read_u32_be(len_buf);

    if (file_len == 0 || file_len > MAX_FILE_BYTES) {
        std::string err = "{\"error\":\"file size out of range\"}";
        send_response(client_fd, noxos::kStatusMalformedInput, err);
        return;
    }

    std::vector<uint8_t> file_bytes(file_len);
    if (!read_exact(client_fd, file_bytes.data(), file_len)) {
        std::string err = "{\"error\":\"incomplete file data received\"}";
        send_response(client_fd, noxos::kStatusMalformedInput, err);
        return;
    }

    std::string result_json;
    uint8_t status = (uint8_t)noxos::ParseExif(file_bytes, result_json);
    send_response(client_fd, status, result_json);
}

extern "C" int AVmPayload_main() {
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
    handle_scan(client_fd);
    close(client_fd);
    close(server_fd);

    printf("noxos-payload: scan complete, exiting\n");
    return 0;
}
