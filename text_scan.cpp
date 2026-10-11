#include "text_scan.h"

#include <algorithm>
#include <cctype>
#include <cstring>

#include "scan_util.h"

namespace noxos {
namespace {

constexpr size_t kMaxScanBytes = 8 * 1024 * 1024;
constexpr size_t kSniffBytes = 2048;
constexpr size_t kBlobBase64Run = 2048;
constexpr size_t kAtobBase64Run = 512;
constexpr size_t kMaxHandlerLetters = 24;
constexpr size_t kProximity = 4096;
constexpr size_t kMinEncodedArg = 24;
constexpr size_t kMaxPositions = 256;
constexpr size_t kMaxRuns = 64;
constexpr size_t kPowershellFlagWindow = 160;
constexpr size_t kCradleDistance = 1024;
constexpr size_t kShellDecodeDistance = 200;

struct Flags {
    std::string first;
    size_t count = 0;
    void Add(std::string reason) {
        if (count++ == 0) first = std::move(reason);
    }
};

std::string LowerWindow(const std::vector<uint8_t>& b, size_t n) {
    std::string s(reinterpret_cast<const char*>(b.data()), n);
    for (char& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

size_t SkipBomAndSpace(const std::vector<uint8_t>& b) {
    size_t i = 0;
    if (b.size() >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) i = 3;
    while (i < b.size() && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n')) i++;
    return i;
}

bool Has(const std::string& s, const char* needle) { return s.find(needle) != std::string::npos; }

size_t Count(const std::string& s, const char* needle) {
    size_t n = 0, pos = 0, len = strlen(needle);
    while ((pos = s.find(needle, pos)) != std::string::npos) {
        n++;
        pos += len;
    }
    return n;
}

size_t CountEventHandlers(const std::string& s) {
    size_t n = 0;
    for (size_t i = 1; i + 4 < s.size(); i++) {
        if (s[i] != 'o' || s[i + 1] != 'n') continue;
        char prev = s[i - 1];
        if (!(prev == ' ' || prev == '\t' || prev == '\n' || prev == '\r' || prev == '"' ||
              prev == '\'' || prev == '/')) {
            continue;
        }
        size_t j = i + 2;
        while (j < s.size() && j - i - 2 < kMaxHandlerLetters && s[j] >= 'a' && s[j] <= 'z') j++;
        if (j - i - 2 < 3) continue;
        while (j < s.size() && (s[j] == ' ' || s[j] == '\t')) j++;
        if (j < s.size() && s[j] == '=') n++;
    }
    return n;
}

size_t MaxBase64Run(const std::string& s) {
    size_t best = 0, cur = 0;
    for (char c : s) {
        bool b64 = isalnum((unsigned char)c) || c == '+' || c == '/' || c == '=';
        if (b64) {
            if (++cur > best) best = cur;
        } else {
            cur = 0;
        }
    }
    return best;
}

bool IsWordChar(char c) { return isalnum((unsigned char)c) || c == '_'; }

bool HasWord(const std::string& s, const char* word) {
    size_t len = strlen(word), pos = 0;
    while ((pos = s.find(word, pos)) != std::string::npos) {
        bool left = pos == 0 || !IsWordChar(s[pos - 1]);
        bool right = pos + len >= s.size() || !IsWordChar(s[pos + len]);
        if (left && right) return true;
        pos += len;
    }
    return false;
}

std::vector<size_t> Positions(const std::string& s, const char* needle) {
    std::vector<size_t> v;
    size_t pos = 0, len = strlen(needle);
    while (v.size() < kMaxPositions && (pos = s.find(needle, pos)) != std::string::npos) {
        v.push_back(pos);
        pos += len;
    }
    return v;
}

struct Run {
    size_t start;
    size_t end;
};

std::vector<Run> LongBase64Runs(const std::string& s, size_t min_len) {
    std::vector<Run> runs;
    size_t cur = 0;
    for (size_t i = 0; i <= s.size(); i++) {
        bool b64 = i < s.size() && (isalnum((unsigned char)s[i]) || s[i] == '+' || s[i] == '/' || s[i] == '=');
        if (b64) {
            cur++;
        } else {
            if (cur >= min_len && runs.size() < kMaxRuns) runs.push_back({i - cur, i});
            cur = 0;
        }
    }
    return runs;
}

size_t Distance(const Run& r, size_t pos) {
    if (pos < r.start) return r.start - pos;
    if (pos > r.end) return pos - r.end;
    return 0;
}

size_t Gap(size_t a, size_t b) { return a > b ? a - b : b - a; }

bool AnyNear(const std::vector<size_t>& v, size_t pos) {
    for (size_t p : v) {
        if (Gap(p, pos) <= kProximity) return true;
    }
    return false;
}

bool AnyRunNear(const std::vector<Run>& runs, size_t min_len, size_t pos) {
    for (const Run& r : runs) {
        if (r.end - r.start >= min_len && Distance(r, pos) <= kProximity) return true;
    }
    return false;
}

bool EncodedArgFollows(const std::string& s, size_t from) {
    size_t i = from;
    while (i < s.size() && (s[i] == ' ' || s[i] == '"' || s[i] == '\'' || s[i] == '\t')) i++;
    size_t n = 0;
    while (i + n < s.size() && (isalnum((unsigned char)s[i + n]) || s[i + n] == '+' || s[i + n] == '/' || s[i + n] == '=')) n++;
    return n >= kMinEncodedArg;
}

bool PowershellEncoded(const std::string& s) {
    static const char* const kFlags[] = {" -encodedcommand ", " -encodedcommand\"", " -enc ", " -ec ", " -e "};
    size_t pos = 0;
    while ((pos = s.find("powershell", pos)) != std::string::npos) {
        size_t end = std::min(s.size(), pos + kPowershellFlagWindow);
        for (const char* flag : kFlags) {
            size_t f = s.find(flag, pos);
            if (f != std::string::npos && f < end && EncodedArgFollows(s, f + strlen(flag))) return true;
        }
        pos += 10;
    }
    size_t e = 0;
    while ((e = s.find("-encodedcommand", e)) != std::string::npos) {
        if (EncodedArgFollows(s, e + 15)) return true;
        e += 15;
    }
    return false;
}

std::vector<size_t> WordPositions(const std::string& s, const char* word) {
    std::vector<size_t> v;
    size_t len = strlen(word), pos = 0;
    while (v.size() < kMaxPositions && (pos = s.find(word, pos)) != std::string::npos) {
        bool left = pos == 0 || !IsWordChar(s[pos - 1]);
        bool right = pos + len >= s.size() || !IsWordChar(s[pos + len]);
        if (left && right) v.push_back(pos);
        pos += len;
    }
    return v;
}

std::vector<size_t> NonKeyPositions(const std::string& s, const char* needle) {
    std::vector<size_t> v;
    size_t len = strlen(needle);
    for (size_t pos : Positions(s, needle)) {
        size_t idx = pos + len;
        if (idx < s.size() && (s[idx] == '"' || s[idx] == '\'')) idx++;
        if (idx < s.size() && s[idx] == ':') continue;
        v.push_back(pos);
    }
    return v;
}

std::vector<size_t> CallPositions(const std::string& s, const char* word, bool allow_pipe_prefix) {
    std::vector<size_t> v;
    size_t len = strlen(word);
    for (size_t pos : WordPositions(s, word)) {
        size_t idx = pos + len;
        while (idx < s.size() && (s[idx] == ' ' || s[idx] == '\t')) idx++;
        char next = idx < s.size() ? s[idx] : '\0';
        bool call = next == '(' || next == '$' || next == '"' || next == '\'' || next == '-' ||
                    s.compare(idx, 4, "http") == 0;
        bool piped = allow_pipe_prefix && pos >= 2 && s.compare(pos - 2, 2, "| ") == 0;
        if (call || piped) v.push_back(pos);
    }
    return v;
}

std::vector<size_t> PipeShellPositions(const std::string& s) {
    std::vector<size_t> v;
    for (const char* p : {"| sh", "|sh", "| bash", "|bash"}) {
        size_t len = strlen(p), pos = 0;
        while (v.size() < kMaxPositions && (pos = s.find(p, pos)) != std::string::npos) {
            if (pos + len >= s.size() || !IsWordChar(s[pos + len])) v.push_back(pos);
            pos += len;
        }
    }
    return v;
}

void Append(std::vector<size_t>& dst, const std::vector<size_t>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

bool NearEach(const std::vector<size_t>& a, const std::vector<size_t>& b, size_t dist) {
    for (size_t x : a) {
        for (size_t y : b) {
            if (Gap(x, y) <= dist) return true;
        }
    }
    return false;
}

std::string ScriptBlocks(const std::string& s) {
    std::string out;
    size_t pos = 0;
    while ((pos = s.find("<script", pos)) != std::string::npos && out.size() < kMaxScanBytes) {
        size_t open_end = s.find('>', pos);
        if (open_end == std::string::npos) break;
        size_t close = s.find("</script", open_end);
        if (close == std::string::npos) close = s.size();
        out.append(s, open_end + 1, close - open_end - 1);
        out.push_back('\n');
        pos = close;
    }
    return out;
}

}  // namespace

bool LooksLikeSvg(const std::vector<uint8_t>& b) {
    size_t i = SkipBomAndSpace(b);
    if (i >= b.size() || b[i] != '<') return false;
    size_t n = std::min(b.size() - i, kSniffBytes);
    std::string head = LowerWindow(std::vector<uint8_t>(b.begin() + (ptrdiff_t)i, b.begin() + (ptrdiff_t)(i + n)), n);
    return Has(head, "<svg") && !Has(head, "<html");
}

bool LooksLikeHtml(const std::vector<uint8_t>& b) {
    size_t i = SkipBomAndSpace(b);
    if (i >= b.size() || b[i] != '<') return false;
    size_t n = std::min(b.size() - i, kSniffBytes);
    std::string head = LowerWindow(std::vector<uint8_t>(b.begin() + (ptrdiff_t)i, b.begin() + (ptrdiff_t)(i + n)), n);
    return head.compare(0, 14, "<!doctype html") == 0 || Has(head, "<html") || head.compare(0, 5, "<head") == 0 ||
           head.compare(0, 5, "<body") == 0 || head.compare(0, 7, "<script") == 0 ||
           head.compare(0, 7, "<iframe") == 0;
}

bool IsScriptExtension(const std::string& ext) {
    static const char* const kExts[] = {"js", "jse", "vbs", "vbe", "ps1", "bat", "cmd", "sh", "hta", "wsf", "wsh"};
    for (const char* e : kExts) {
        if (ext == e) return true;
    }
    return false;
}

CheapFilterResult ScanText(const std::vector<uint8_t>& b, const std::string& type, std::string& out_json) {
    Flags flags;
    size_t n = std::min(b.size(), kMaxScanBytes);
    std::string s = LowerWindow(b, n);
    bool truncated = b.size() > n;

    if (const char* sig = FindKnownBadSignature(b.data(), b.size())) {
        flags.Add(std::string("contains ") + sig);
    }

    size_t script_tags = Count(s, "<script");
    size_t handlers = CountEventHandlers(s);
    size_t js_urls = Count(s, "javascript:");
    size_t b64_run = MaxBase64Run(s);
    size_t pipe_to_shell = 0;
    pipe_to_shell = PipeShellPositions(s).size();

    const std::string active = type == "script" ? s : ScriptBlocks(s);
    bool blob_api = Has(s, "new blob(") || Has(s, "createobjecturl") || Has(s, "mssaveoropenblob");
    bool atob = Has(s, "atob(");

    std::vector<size_t> blob_pos = Positions(active, "new blob(");
    for (size_t p : Positions(active, "createobjecturl")) blob_pos.push_back(p);
    for (size_t p : Positions(active, "mssaveoropenblob")) blob_pos.push_back(p);
    std::vector<size_t> trigger_pos = Positions(active, ".click()");
    for (const char* t : {"download=", ".download", "mssaveoropenblob"}) {
        for (size_t p : Positions(active, t)) trigger_pos.push_back(p);
    }
    std::vector<size_t> atob_pos = Positions(active, "atob(");
    std::vector<Run> runs = LongBase64Runs(active, kAtobBase64Run);
    bool smuggle = false;
    for (size_t bp : blob_pos) {
        if (!AnyNear(trigger_pos, bp)) continue;
        bool literal = AnyRunNear(runs, kBlobBase64Run, bp);
        bool via_atob = false;
        for (size_t ap : atob_pos) {
            if (Gap(ap, bp) <= kProximity && AnyRunNear(runs, kAtobBase64Run, ap)) via_atob = true;
        }
        if (literal || via_atob) {
            smuggle = true;
            break;
        }
    }

    bool eval_decode = Has(active, "eval(atob(") || Has(active, "eval(unescape(") ||
                       Has(active, "eval(string.fromcharcode") || Has(active, "new function(atob(") ||
                       Has(active, "document.write(unescape(") || Has(active, "eval(decodeuricomponent(") ||
                       Has(active, "settimeout(atob(");

    bool ps = HasWord(active, "powershell") || Has(active, "invoke-expression") ||
              Has(active, "frombase64string") || Has(active, "downloadstring") || Has(active, "downloadfile") ||
              Has(active, "iwr ") || Has(active, "irm ");
    bool ps_encoded = PowershellEncoded(active);
    std::vector<size_t> iex_pos = CallPositions(active, "iex", true);
    Append(iex_pos, NonKeyPositions(active, "invoke-expression"));
    std::vector<size_t> download_pos = Positions(active, "downloadstring");
    for (const char* w : {"downloadfile", "invoke-webrequest", "invoke-restmethod"}) Append(download_pos, NonKeyPositions(active, w));
    for (const char* w : {"iwr", "irm"}) Append(download_pos, CallPositions(active, w, false));
    std::vector<size_t> b64_pos = Positions(active, "frombase64string");
    bool ps_hidden = Has(active, "-windowstyle hidden") || Has(active, "-w hidden") || Has(active, "-windowstyle 1");
    bool ps_cradle = ps && (NearEach(b64_pos, iex_pos, kCradleDistance) || NearEach(download_pos, iex_pos, kCradleDistance) ||
                            (ps_hidden && (Has(active, "downloadstring") || Has(active, "downloadfile") ||
                                           ps_encoded || !b64_pos.empty())));

    bool wsh = (Has(active, "wscript.shell") || Has(active, "shell.application")) &&
               (Has(active, ".run(") || Has(active, ".exec(") || Has(active, ".run ") || Has(active, "shellexecute"));
    bool lolbin = (HasWord(active, "regsvr32") && Has(active, "scrobj.dll")) ||
                  (HasWord(active, "certutil") && (Has(active, "-urlcache") || Has(active, "-decode"))) ||
                  (HasWord(active, "mshta") && Has(active, "http")) ||
                  (HasWord(active, "bitsadmin") && Has(active, "/transfer"));
    bool is_script = type == "script";
    std::vector<size_t> decode_pos = Positions(s, "base64 -d");
    Append(decode_pos, Positions(s, "base64 --decode"));
    std::vector<size_t> sink_pos = PipeShellPositions(s);
    Append(sink_pos, WordPositions(s, "eval"));
    bool shell_decode = is_script && NearEach(decode_pos, sink_pos, kShellDecodeDistance);
    bool reverse_shell = is_script && Has(s, "/dev/tcp/") && (Has(s, "bash -i") || Has(s, ">&") || Has(s, "sh -i"));

    if (type == "svg") {
        if (script_tags > 0) flags.Add("SVG contains a <script> element");
        if (handlers > 0) flags.Add("SVG contains " + std::to_string(handlers) + " event-handler attribute(s)");
        if (js_urls > 0) flags.Add("SVG contains a javascript: URL");
        if (Has(s, "<foreignobject") && (Has(s, "<iframe") || Has(s, "<object") || Has(s, "<embed"))) {
            flags.Add("SVG embeds an iframe/object inside foreignObject");
        }
    }
    if (smuggle) {
        flags.Add("HTML smuggling pattern: a decoded embedded blob is assembled and saved through a Blob download");
    }
    if (eval_decode) flags.Add("script evaluates an encoded or escaped string (eval of decoded data)");
    if (ps_encoded) flags.Add("PowerShell encoded command");
    if (ps_cradle) flags.Add("PowerShell download-and-execute or base64-execute pattern");
    if (wsh) flags.Add("script launches programs through WScript.Shell/Shell.Application");
    if (lolbin) flags.Add("script abuses a living-off-the-land binary (regsvr32/certutil/mshta/bitsadmin)");
    if (shell_decode) flags.Add("shell script decodes base64 and pipes it to a shell");
    if (reverse_shell) flags.Add("shell script opens a /dev/tcp reverse shell");

    out_json = "{\"file_type\":\"" + type + "\",\"text_bytes\":" + std::to_string(b.size()) +
               ",\"text_truncated\":" + (truncated ? "true" : "false") +
               ",\"text_script_tags\":" + std::to_string(script_tags) +
               ",\"text_event_handlers\":" + std::to_string(handlers) +
               ",\"text_js_urls\":" + std::to_string(js_urls) +
               ",\"text_base64_run_max\":" + std::to_string(b64_run) +
               ",\"text_blob_api\":" + (blob_api ? "true" : "false") +
               ",\"text_atob\":" + (atob ? "true" : "false") +
               ",\"text_pipe_to_shell\":" + std::to_string(pipe_to_shell) +
               ",\"text_flag_count\":" + std::to_string(flags.count) + "}";
    CheapFilterResult r;
    r.flagged = flags.count > 0;
    r.reason = flags.first;
    return r;
}

}  // namespace noxos
