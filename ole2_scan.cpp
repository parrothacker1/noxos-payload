#include "ole2_scan.h"

#include <algorithm>
#include <cctype>
#include <cstring>

#include "scan_util.h"

namespace noxos {
namespace {

constexpr uint32_t kFree = 0xFFFFFFFF;
constexpr uint32_t kEnd = 0xFFFFFFFE;
constexpr size_t kHeaderDifat = 109;
constexpr size_t kMaxDirEntries = 100000;
constexpr size_t kMaxBiffBytes = 1024 * 1024;
constexpr size_t kMaxBiffRecords = 200000;
constexpr size_t kTailTolerance = 2;

constexpr uint16_t kBiffBoundSheet = 0x0085;
constexpr uint16_t kBiffFilePass = 0x002F;
constexpr uint16_t kBiffEof = 0x000A;

struct Flags {
    std::string first;
    size_t count = 0;
    void Add(std::string reason) {
        if (count++ == 0) first = std::move(reason);
    }
};

struct DirEntry {
    std::string name;
    uint8_t type = 0;
    uint32_t start = 0;
    uint64_t size = 0;
};

struct Cfb {
    const std::vector<uint8_t>& b;
    size_t ssz = 512;
    size_t total = 0;
    std::vector<uint32_t> fat;

    explicit Cfb(const std::vector<uint8_t>& bytes) : b(bytes) {}

    const uint8_t* Sector(uint32_t n) const {
        if (n >= total) return nullptr;
        return b.data() + (size_t)(n + 1) * ssz;
    }
};

std::string Lower(std::string s) {
    for (char& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

bool ReadStream(const Cfb& c, uint32_t start, uint64_t size, size_t max, std::vector<uint8_t>& out) {
    out.clear();
    size_t want = (size_t)std::min<uint64_t>(size, max);
    uint32_t cur = start;
    size_t steps = 0;
    while (out.size() < want) {
        const uint8_t* p = c.Sector(cur);
        if (!p || cur >= c.fat.size()) return false;
        size_t take = std::min(c.ssz, want - out.size());
        out.insert(out.end(), p, p + take);
        uint32_t next = c.fat[cur];
        if (out.size() >= want || next == kEnd) break;
        if (++steps > c.total) return false;
        cur = next;
    }
    return out.size() == want;
}

struct Biff {
    size_t xlm_sheets = 0;
    size_t hidden_xlm_sheets = 0;
    size_t vba_module_sheets = 0;
    bool encrypted = false;
};

Biff WalkBiff(const std::vector<uint8_t>& d) {
    Biff r;
    size_t pos = 0;
    for (size_t n = 0; n < kMaxBiffRecords && d.size() - pos >= 4; n++) {
        uint16_t id = ReadU16Le(d.data() + pos);
        size_t len = ReadU16Le(d.data() + pos + 2);
        if (d.size() - pos - 4 < len) break;
        const uint8_t* body = d.data() + pos + 4;
        if (id == kBiffBoundSheet && len >= 6) {
            uint8_t hidden = body[4] & 3;
            uint8_t type = body[5];
            if (type == 1) {
                r.xlm_sheets++;
                if (hidden) r.hidden_xlm_sheets++;
            }
            if (type == 6) r.vba_module_sheets++;
        }
        if (id == kBiffFilePass) r.encrypted = true;
        if (id == kBiffEof && n > 0) break;
        pos += 4 + len;
    }
    return r;
}

}  // namespace

CheapFilterResult ScanOle2(const std::vector<uint8_t>& b, std::string& out_json) {
    Flags flags;
    Cfb c(b);
    size_t entries = 0;
    bool macros = false;
    bool encrypted_package = false;
    size_t embedded = 0;
    size_t equation = 0;
    Biff biff;
    bool header_ok = false;

    if (const char* sig = FindKnownBadSignature(b.data(), b.size())) {
        flags.Add(std::string("contains ") + sig);
    }

    do {
        if (b.size() < 512) {
            flags.Add("OLE2 file is shorter than its 512-byte header");
            break;
        }
        const uint8_t* h = b.data();
        uint16_t major = ReadU16Le(h + 26);
        uint16_t order = ReadU16Le(h + 28);
        uint16_t shift = ReadU16Le(h + 30);
        uint16_t mini_shift = ReadU16Le(h + 32);
        if (order != 0xFFFE || (major != 3 && major != 4) || (major == 3 && shift != 9) ||
            (major == 4 && shift != 12) || mini_shift != 6) {
            flags.Add("OLE2 header has inconsistent version, byte order, or sector size");
            break;
        }
        header_ok = true;
        c.ssz = (size_t)1 << shift;
        c.total = b.size() >= c.ssz ? b.size() / c.ssz - 1 : 0;
        uint32_t num_fat = ReadU32Le(h + 44);
        uint32_t first_dir = ReadU32Le(h + 48);
        uint32_t cutoff = ReadU32Le(h + 56);
        uint32_t first_difat = ReadU32Le(h + 68);
        uint32_t num_difat = ReadU32Le(h + 72);

        std::vector<uint32_t> fat_ids;
        for (size_t i = 0; i < kHeaderDifat; i++) {
            uint32_t id = ReadU32Le(h + 76 + 4 * i);
            if (id == kFree) break;
            fat_ids.push_back(id);
        }
        uint32_t s = first_difat;
        for (uint32_t n = 0; n < num_difat && n <= c.total && s != kEnd && s != kFree; n++) {
            const uint8_t* p = c.Sector(s);
            if (!p) {
                flags.Add("OLE2 DIFAT sector lies outside the file");
                break;
            }
            for (size_t j = 0; j + 1 < c.ssz / 4; j++) {
                uint32_t id = ReadU32Le(p + 4 * j);
                if (id != kFree) fat_ids.push_back(id);
            }
            s = ReadU32Le(p + c.ssz - 4);
        }
        if (fat_ids.size() > c.total || (num_fat != 0 && fat_ids.size() != num_fat)) {
            flags.Add("OLE2 FAT sector count does not match its header");
        }
        for (uint32_t id : fat_ids) {
            const uint8_t* p = c.Sector(id);
            if (!p) {
                flags.Add("OLE2 FAT sector lies outside the file");
                continue;
            }
            for (size_t j = 0; j < c.ssz / 4; j++) c.fat.push_back(ReadU32Le(p + 4 * j));
        }

        std::vector<DirEntry> dir;
        uint32_t cur = first_dir;
        size_t steps = 0;
        while (cur != kEnd && dir.size() < kMaxDirEntries) {
            const uint8_t* p = c.Sector(cur);
            if (!p || cur >= c.fat.size()) {
                flags.Add("OLE2 directory chain leaves the file");
                break;
            }
            for (size_t off = 0; off + 128 <= c.ssz && dir.size() < kMaxDirEntries; off += 128) {
                const uint8_t* e = p + off;
                DirEntry d;
                d.type = e[66];
                size_t name_len = ReadU16Le(e + 64);
                if (d.type == 0 || name_len < 2 || name_len > 64) continue;
                for (size_t k = 0; k + 2 <= name_len - 2; k += 2) {
                    uint16_t ch = ReadU16Le(e + k);
                    d.name += ch < 0x80 ? (char)ch : '?';
                }
                d.start = ReadU32Le(e + 116);
                d.size = c.ssz == 512 ? ReadU32Le(e + 120) : ReadU64Le(e + 120);
                dir.push_back(std::move(d));
            }
            if (++steps > c.total) {
                flags.Add("OLE2 directory chain loops");
                break;
            }
            cur = c.fat[cur];
        }
        entries = dir.size();

        const DirEntry* workbook = nullptr;
        for (const auto& d : dir) {
            std::string n = Lower(d.name);
            if (n == "vba" || n == "_vba_project" || n == "_vba_project_cur" || n == "macros" ||
                n == "projectwm") {
                macros = true;
            }
            if (n == "encryptedpackage") encrypted_package = true;
            if (n == "\x01ole10native" || n == "objectpool") embedded++;
            if (n == "equation native") equation++;
            if ((n == "workbook" || n == "book") && d.type == 2) workbook = &d;
        }
        if (workbook && workbook->size >= cutoff) {
            std::vector<uint8_t> wb;
            if (ReadStream(c, workbook->start, workbook->size, kMaxBiffBytes, wb)) biff = WalkBiff(wb);
        }

        size_t last_used = 0;
        bool any_used = false;
        for (size_t i = 0; i < c.fat.size(); i++) {
            if (c.fat[i] != kFree) {
                last_used = i;
                any_used = true;
            }
        }
        if (any_used) {
            size_t expected_end = (last_used + 2 + kTailTolerance) * c.ssz;
            if (b.size() > expected_end) {
                if (const char* m = FindForeignMagic(b, expected_end)) {
                    flags.Add(std::string("embedded ") + m + " signature after the last used OLE2 sector");
                }
            }
        }
    } while (false);

    if (macros || biff.vba_module_sheets > 0) flags.Add("OLE2 document contains a VBA project (macros)");
    if (biff.xlm_sheets > 0) {
        flags.Add(std::string("OLE2 workbook contains ") +
                  (biff.hidden_xlm_sheets > 0 ? "a hidden " : "an ") + "Excel 4.0 (XLM) macro sheet");
    }
    bool encrypted = encrypted_package || biff.encrypted;
    if (encrypted) flags.Add("OLE2 document is encrypted; its contents cannot be inspected");

    out_json = "{\"file_type\":\"ole2\",\"ole2_header_ok\":" + std::string(header_ok ? "true" : "false") +
               ",\"ole2_sector_size\":" + std::to_string(c.ssz) +
               ",\"ole2_entries\":" + std::to_string(entries) +
               ",\"ole2_macros\":" + (macros || biff.vba_module_sheets > 0 ? "true" : "false") +
               ",\"ole2_xlm_sheets\":" + std::to_string(biff.xlm_sheets) +
               ",\"ole2_encrypted\":" + (encrypted ? "true" : "false") +
               ",\"ole2_embedded_objects\":" + std::to_string(embedded) +
               ",\"ole2_equation_objects\":" + std::to_string(equation) +
               ",\"ole2_flag_count\":" + std::to_string(flags.count) + "}";
    CheapFilterResult r;
    r.flagged = flags.count > 0;
    r.reason = flags.first;
    return r;
}

}  // namespace noxos
