#include "../pdf_scan.h"

#include <zlib.h>

#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> Bytes(const std::string& s) { return std::vector<uint8_t>(s.begin(), s.end()); }

std::string Zlib(const std::string& in) {
    uLongf n = compressBound(in.size());
    std::string out(n, '\0');
    compress2(reinterpret_cast<Bytef*>(&out[0]), &n, reinterpret_cast<const Bytef*>(in.data()),
              in.size(), 9);
    out.resize(n);
    return out;
}

std::string Pdf(const std::string& body, const std::string& after_eof = "\n") {
    std::string p = "%PDF-1.7\n" + body;
    size_t xref = p.size();
    p += "xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n" +
         std::to_string(xref) + "\n%%EOF" + after_eof;
    return p;
}

noxos::CheapFilterResult Scan(const std::string& pdf, std::string* json = nullptr) {
    std::string j;
    auto r = noxos::ScanPdf(Bytes(pdf), j);
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
    const std::string catalog = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction [3 0 R /Fit] >>\nendobj\n";
    {
        std::string j;
        auto r = Scan(Pdf(catalog), &j);
        if (r.flagged) fprintf(stderr, "%s\n", r.reason.c_str());
        assert(!r.flagged);
        assert(j.find("\"pdf_version\":\"1.7\"") != std::string::npos);
        assert(j.find("\"pdf_startxref_valid\":true") != std::string::npos);
        assert(j.find("\"pdf_openaction\":1") != std::string::npos);
    }
    {
        std::string body = "1 0 obj\n<< /OpenAction 2 0 R >>\nendobj\n2 0 obj\n<< /S /JavaScript /JS (app.alert(1)) >>\nendobj\n";
        assert(Has(Scan(Pdf(body)), "JavaScript automatically"));
    }
    {
        std::string hidden = "<< /S /JavaScript /JS (this.exportDataObject({cName:'x', nLaunch:2})) >>";
        std::string body = "1 0 obj\n<< /Type /Catalog /AA << /O 5 0 R >> >>\nendobj\n"
                           "4 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode >>\nstream\n" +
                           Zlib("5 0 " + hidden) + "\nendstream\nendobj\n";
        std::string j;
        assert(Has(Scan(Pdf(body), &j), "JavaScript automatically"));
        assert(j.find("\"pdf_inflated_streams\":1") != std::string::npos);
    }
    {
        std::string body = "1 0 obj\n<< /OpenAction 2 0 R >>\nendobj\n2 0 obj\n<< /S /J#61vaScript /JS (x) >>\nendobj\n";
        assert(Has(Scan(Pdf(body)), "hex-obfuscated PDF name /JavaScript"));
    }
    assert(Has(Scan(Pdf("1 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n")), "/Launch"));
    assert(Has(Scan(Pdf(catalog, "\n" + std::string(2000, 'Z'))), "after the final %%EOF"));
    assert(!Scan(Pdf(catalog, "\r\n\n  \n")).flagged);
    assert(Has(Scan("GARBAGE!" + Pdf(catalog)), "before the %PDF- header"));
    assert(Has(Scan("%PDF-1.4\n1 0 obj\n<< >>\nendobj\n"), "no %%EOF"));
    assert(Has(Scan("%PDF-1.4\nstartxref\n999999999\n%%EOF\n"), "past the end"));
    {
        std::string j;
        auto r = Scan(Pdf("7 0 obj\n<< >>\nendobj\n"), &j);
        assert(j.find("\"pdf_startxref_valid\":true") != std::string::npos);
        std::string xs = "%PDF-1.4\n7 0 obj\n<< /Type /XRef >>\nendobj\nstartxref\n9\n%%EOF\n";
        Scan(xs, &j);
        assert(j.find("\"pdf_startxref_valid\":true") != std::string::npos);
    }
    {
        std::string j;
        auto r = Scan("%PDF-1.4\nstartxref\n5\n%%EOF\n", &j);
        assert(!r.flagged);
        assert(j.find("\"pdf_startxref_valid\":false") != std::string::npos);
    }
    assert(Has(Scan(Pdf("% X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n")),
               "EICAR"));
    {
        std::string body = "1 0 obj\n<< /Type /EmbeddedFile >>\nstream\n" + Zlib("MZ fake") +
                           "\nendstream\nendobj\n";
        assert(!Scan(Pdf(catalog + body)).flagged);
    }
    {
        std::string body = "1 0 obj\n<< /Length 5 >>\nstream\n\x78\x9C\xFF\xFF\xFF\nendstream\nendobj\n";
        assert(!Scan(Pdf(body)).flagged);
        Scan("%PDF-1.4\n1 0 obj\nstream\n");
    }

    printf("ok: pdf_scan_test passed\n");
    return 0;
}
