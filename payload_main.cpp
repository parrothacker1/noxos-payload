// noxos-payload: EXIF parser payload for Microdroid pVM
//
// Listens on vsock port 5000 for a single scan request, parses JPEG EXIF
// metadata from the received file bytes, and returns a JSON result to the
// host app (noxos-app / TriggerRouter).
//
// Wire protocol (matches VmPayloadProtocol.kt exactly):
//   Host → Guest:  [4-byte big-endian length][raw file bytes]
//   Guest → Host:  [4-byte big-endian length][1-byte status][UTF-8 JSON]
//     Status: 0 = OK, 1 = PARSE_ERROR, 2 = MALFORMED_INPUT
//
// EXIF parsing is intentionally minimal and self-contained (no libexif or
// similar third-party dependency): reads JPEG APP1 segment, walks the IFD0
// tag table for a curated set of human-readable tags. This is deliberately
// scoped to one payload type (JPEG EXIF) — see PROJECT.md "don't build a
// general malware-detonation engine."
//
// This file replaces the P2 stub (payload_main.cpp). The structure is:
//   1. AVmPayload_main() — entry point, opens vsock listener
//   2. handle_scan()     — reads request, calls parse_exif(), sends response
//   3. parse_exif()      — pure function: bytes → JSON string
//   4. read_u16/read_u32 — byte-order helpers

#include <vm_payload/api.h>

#include <arpa/inet.h>
#include <errno.h>
#include <linux/vm_sockets.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <vector>

// Vsock port — must match VmPayloadProtocol.VSOCK_PORT in noxos-app.
static constexpr uint32_t VSOCK_PORT = 5000;

// Wire protocol status codes — must match VmPayloadProtocol response codes.
static constexpr uint8_t STATUS_OK = 0;
static constexpr uint8_t STATUS_PARSE_ERROR = 1;
static constexpr uint8_t STATUS_MALFORMED_INPUT = 2;

// Maximum file size accepted: 10 MB. Reject anything larger outright.
static constexpr size_t MAX_FILE_BYTES = 10 * 1024 * 1024;

// ─── Byte-order helpers ────────────────────────────────────────────────────

static uint16_t read_u16_be(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint16_t read_u16_le(const uint8_t* p) {
    return (uint16_t)((p[1] << 8) | p[0]);
}

static uint32_t read_u32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static uint32_t read_u32_le(const uint8_t* p) {
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8)  | (uint32_t)p[0];
}

// ─── JSON helpers ─────────────────────────────────────────────────────────

// Escape a string for embedding as a JSON value (handles " and \).
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        if (c == '"')       out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else                out += c;
    }
    return out;
}

// ─── EXIF tag name lookup ─────────────────────────────────────────────────

struct ExifTagDef {
    uint16_t    tag;
    const char* name;
};

// Curated IFD0 / Exif SubIFD tags that are safe and human-meaningful.
static const ExifTagDef kKnownTags[] = {
    { 0x010F, "Make" },
    { 0x0110, "Model" },
    { 0x0112, "Orientation" },
    { 0x011A, "XResolution" },
    { 0x011B, "YResolution" },
    { 0x0128, "ResolutionUnit" },
    { 0x0131, "Software" },
    { 0x0132, "DateTime" },
    { 0x013B, "Artist" },
    { 0x013E, "WhitePoint" },
    { 0x013F, "PrimaryChromaticities" },
    { 0x0213, "YCbCrPositioning" },
    { 0x8298, "Copyright" },
    { 0x8769, "ExifIFDPointer" },
    { 0x9000, "ExifVersion" },
    { 0x9003, "DateTimeOriginal" },
    { 0x9004, "DateTimeDigitized" },
    { 0x9101, "ComponentsConfiguration" },
    { 0x9102, "CompressedBitsPerPixel" },
    { 0x9201, "ShutterSpeedValue" },
    { 0x9202, "ApertureValue" },
    { 0x9204, "ExposureBiasValue" },
    { 0x9205, "MaxApertureValue" },
    { 0x9207, "MeteringMode" },
    { 0x9208, "LightSource" },
    { 0x9209, "Flash" },
    { 0x920A, "FocalLength" },
    { 0xA001, "ColorSpace" },
    { 0xA002, "PixelXDimension" },
    { 0xA003, "PixelYDimension" },
    { 0xA402, "ExposureMode" },
    { 0xA403, "WhiteBalance" },
    { 0xA404, "DigitalZoomRatio" },
    { 0xA405, "FocalLengthIn35mmFilm" },
    { 0xA406, "SceneCaptureType" },
    { 0xA408, "Contrast" },
    { 0xA409, "Saturation" },
    { 0xA40A, "Sharpness" },
    { 0xA433, "LensMake" },
    { 0xA434, "LensModel" },
    { 0x8825, "GPSInfoIFDPointer" },
};

static const char* exif_tag_name(uint16_t tag) {
    for (size_t i = 0; i < sizeof(kKnownTags) / sizeof(kKnownTags[0]); i++) {
        if (kKnownTags[i].tag == tag) return kKnownTags[i].name;
    }
    return nullptr;
}

// ─── IFD entry reader ─────────────────────────────────────────────────────

// EXIF type sizes in bytes.
static size_t exif_type_size(uint16_t type) {
    switch (type) {
        case 1: return 1;   // BYTE
        case 2: return 1;   // ASCII
        case 3: return 2;   // SHORT
        case 4: return 4;   // LONG
        case 5: return 8;   // RATIONAL (two LONGs)
        case 7: return 1;   // UNDEFINED
        case 9: return 4;   // SLONG
        case 10: return 8;  // SRATIONAL
        default: return 0;
    }
}

// Read the value of a single IFD entry into a human-readable string.
// tiff_base is the start of the TIFF header (the "II" or "MM" marker) for
// resolving offset values.
static std::string read_ifd_value(const uint8_t* tiff_base, size_t tiff_len,
                                  const uint8_t* entry, bool little_endian) {
    auto u16 = little_endian ? read_u16_le : read_u16_be;
    auto u32 = little_endian ? read_u32_le : read_u32_be;

    uint16_t type   = u16(entry + 2);
    uint32_t count  = u32(entry + 4);
    size_t   tsz    = exif_type_size(type);

    if (tsz == 0 || count == 0) return "";

    size_t total = tsz * count;
    const uint8_t* vp;
    if (total <= 4) {
        vp = entry + 8;
    } else {
        uint32_t offset = u32(entry + 8);
        if (offset + total > tiff_len) return "";
        vp = tiff_base + offset;
    }

    char buf[64];
    switch (type) {
        case 2: {  // ASCII
            std::string s(reinterpret_cast<const char*>(vp), count);
            // Strip trailing NUL.
            while (!s.empty() && s.back() == '\0') s.pop_back();
            return s;
        }
        case 3: {  // SHORT
            if (count == 1) {
                snprintf(buf, sizeof(buf), "%u", u16(vp));
                return buf;
            }
            // First two values for multi-value SHORTs.
            snprintf(buf, sizeof(buf), "%u,%u", u16(vp),
                     (count > 1 && 2 * 1 + 2 <= (int)total) ? u16(vp + 2) : 0u);
            return buf;
        }
        case 4: {  // LONG
            snprintf(buf, sizeof(buf), "%u", u32(vp));
            return buf;
        }
        case 5:    // RATIONAL
        case 10: { // SRATIONAL
            if (total < 8) return "";
            uint32_t num = u32(vp);
            uint32_t den = u32(vp + 4);
            if (den == 0) return "0";
            snprintf(buf, sizeof(buf), "%u/%u", num, den);
            return buf;
        }
        default:
            return "";
    }
}

// ─── Core EXIF parser ─────────────────────────────────────────────────────

// Walk a TIFF IFD at |ifd_offset| relative to |tiff_base|.
// Appends found key:value pairs to |out_pairs|.
static void walk_ifd(const uint8_t* tiff_base, size_t tiff_len,
                     uint32_t ifd_offset, bool little_endian,
                     std::vector<std::pair<std::string, std::string>>& out_pairs,
                     int depth) {
    // ifd_offset/sub_offset come straight from attacker-controlled file
    // bytes (ExifIFDPointer / GPSInfoIFDPointer tag values). Widen to
    // size_t (64-bit on our target platforms) before any bounds-check
    // arithmetic: doing "ifd_offset + 2 > tiff_len" in 32-bit uint32_t
    // math lets a crafted offset near UINT32_MAX wrap around to a small
    // value, bypassing the check and causing an out-of-bounds heap read.
    size_t offset = ifd_offset;
    if (depth > 2 || offset + 2 > tiff_len) return;

    auto u16 = little_endian ? read_u16_le : read_u16_be;
    auto u32 = little_endian ? read_u32_le : read_u32_be;

    uint16_t entry_count = u16(tiff_base + offset);
    size_t pos = offset + 2;

    for (uint16_t i = 0; i < entry_count; i++) {
        if (pos + 12 > tiff_len) break;

        const uint8_t* entry = tiff_base + pos;
        uint16_t tag = u16(entry);

        const char* name = exif_tag_name(tag);
        if (name) {
            // Recurse into Exif SubIFD and GPS IFD.
            if (tag == 0x8769 || tag == 0x8825) {
                uint32_t sub_offset = u32(entry + 8);
                walk_ifd(tiff_base, tiff_len, sub_offset, little_endian,
                         out_pairs, depth + 1);
            } else {
                std::string val = read_ifd_value(tiff_base, tiff_len,
                                                 entry, little_endian);
                if (!val.empty()) {
                    out_pairs.push_back({name, val});
                }
            }
        }

        pos += 12;
    }
}

// Returns a JSON object string on success, or an error JSON object on failure.
// Caller checks whether the first byte indicates success/failure.
static int parse_exif(const std::vector<uint8_t>& file_bytes,
                      std::string& out_json) {
    const uint8_t* data = file_bytes.data();
    size_t size = file_bytes.size();

    // JPEG must start with FF D8.
    if (size < 4 || data[0] != 0xFF || data[1] != 0xD8) {
        out_json = "{\"error\":\"not a JPEG file\"}";
        return STATUS_MALFORMED_INPUT;
    }

    // Scan JPEG segments for APP1 (FF E1) containing "Exif\0\0".
    size_t pos = 2;
    while (pos + 4 <= size) {
        if (data[pos] != 0xFF) {
            out_json = "{\"error\":\"invalid JPEG segment marker\"}";
            return STATUS_PARSE_ERROR;
        }

        uint8_t marker = data[pos + 1];
        uint16_t seg_len = read_u16_be(data + pos + 2);  // includes the 2-byte length field

        if (marker == 0xE1 && pos + 4 + 6 <= size) {
            // APP1: check for "Exif\0\0" header.
            if (memcmp(data + pos + 4, "Exif\0\0", 6) == 0) {
                // TIFF header starts at pos + 10.
                const uint8_t* tiff = data + pos + 10;
                size_t tiff_len = (pos + 2 + seg_len) - (pos + 10);

                if (tiff_len < 8) {
                    out_json = "{\"error\":\"truncated TIFF header\"}";
                    return STATUS_PARSE_ERROR;
                }

                // TIFF byte-order: "II" = little-endian, "MM" = big-endian.
                bool little_endian = (tiff[0] == 'I' && tiff[1] == 'I');
                bool big_endian    = (tiff[0] == 'M' && tiff[1] == 'M');
                if (!little_endian && !big_endian) {
                    out_json = "{\"error\":\"invalid TIFF byte order marker\"}";
                    return STATUS_PARSE_ERROR;
                }

                auto u32 = little_endian ? read_u32_le : read_u32_be;
                uint32_t ifd0_offset = u32(tiff + 4);

                std::vector<std::pair<std::string, std::string>> pairs;
                walk_ifd(tiff, tiff_len, ifd0_offset, little_endian, pairs, 0);

                if (pairs.empty()) {
                    out_json = "{\"error\":\"no readable EXIF tags found\"}";
                    return STATUS_PARSE_ERROR;
                }

                // Build JSON object.
                std::string json = "{";
                for (size_t k = 0; k < pairs.size(); k++) {
                    if (k > 0) json += ",";
                    json += "\"" + json_escape(pairs[k].first) + "\":";
                    json += "\"" + json_escape(pairs[k].second) + "\"";
                }
                json += "}";
                out_json = json;
                return STATUS_OK;
            }
        }

        // Skip to next segment (seg_len includes its own 2 bytes but not the FF xx marker).
        pos += 2 + seg_len;
    }

    out_json = "{\"error\":\"no EXIF APP1 segment found in JPEG\"}";
    return STATUS_PARSE_ERROR;
}

// ─── Network I/O ──────────────────────────────────────────────────────────

// Read exactly |n| bytes from |fd| into |buf|. Returns false on error/EOF.
static bool read_exact(int fd, uint8_t* buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, buf + done, n - done);
        if (r <= 0) return false;
        done += (size_t)r;
    }
    return true;
}

// Write exactly |n| bytes from |buf| to |fd|. Returns false on error.
static bool write_exact(int fd, const uint8_t* buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, buf + done, n - done);
        if (w <= 0) return false;
        done += (size_t)w;
    }
    return true;
}

// Send a length-prefixed response frame: [4-byte BE length][status][json].
static void send_response(int fd, uint8_t status, const std::string& json) {
    uint32_t json_len = (uint32_t)json.size();
    uint32_t payload_len = 1 + json_len;  // 1 byte status + json bytes

    uint8_t hdr[4];
    hdr[0] = (payload_len >> 24) & 0xFF;
    hdr[1] = (payload_len >> 16) & 0xFF;
    hdr[2] = (payload_len >>  8) & 0xFF;
    hdr[3] = (payload_len      ) & 0xFF;

    write_exact(fd, hdr, 4);
    write_exact(fd, &status, 1);
    write_exact(fd, reinterpret_cast<const uint8_t*>(json.data()), json_len);
}

// Handle one scan request from |client_fd|.
static void handle_scan(int client_fd) {
    // Read 4-byte big-endian length prefix.
    uint8_t len_buf[4];
    if (!read_exact(client_fd, len_buf, 4)) {
        printf("noxos-payload: failed to read length prefix\n");
        return;
    }
    uint32_t file_len = read_u32_be(len_buf);

    if (file_len == 0 || file_len > MAX_FILE_BYTES) {
        std::string err = "{\"error\":\"file size out of range\"}";
        send_response(client_fd, STATUS_MALFORMED_INPUT, err);
        return;
    }

    std::vector<uint8_t> file_bytes(file_len);
    if (!read_exact(client_fd, file_bytes.data(), file_len)) {
        std::string err = "{\"error\":\"incomplete file data received\"}";
        send_response(client_fd, STATUS_MALFORMED_INPUT, err);
        return;
    }

    std::string result_json;
    uint8_t status = (uint8_t)parse_exif(file_bytes, result_json);
    send_response(client_fd, status, result_json);
}

// ─── Entry point ─────────────────────────────────────────────────────────

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

    // Accept one connection, handle it, then exit (ephemeral VM — destroyed
    // by the host after each scan, so we don't loop).
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
