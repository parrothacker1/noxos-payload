<div align="center">

<img src="https://raw.githubusercontent.com/parrothacker1/noxos/main/assets/branding/logo-mark.svg" width="80" height="80" alt="NoxOS Logo">

# noxos-payload

**Native EXIF parser + cheap pre-scan filters running inside the Microdroid guest VM**

![C++](https://img.shields.io/badge/C%2B%2B-17-00599C?style=flat-square&logo=cplusplus&logoColor=white)
![Build](https://img.shields.io/badge/Build-Android.bp%20%2F%20Soong-3DDC84?style=flat-square&logo=android&logoColor=white)
![Entry](https://img.shields.io/badge/Entry%20Point-AVmPayload__main()-4FD1C5?style=flat-square)
![Status](https://img.shields.io/badge/Status-Coded%2C%20Pre--Phase--2-orange?style=flat-square)

</div>

---

## Overview

`noxos-payload` is the native library that executes **inside** the disposable Microdroid pVM launched by `noxos-app`. It receives raw file bytes from the host over vsock, parses their EXIF metadata in complete isolation from the host OS, and returns a JSON result. The VM is then destroyed.

This repo is kept **separate from the other NoxOS repos deliberately**: its commit history is the immutable audit trail for every piece of code that has ever run inside the NoxOS trust boundary.

---

## Why a Separate VM?

Standard Android sandboxing (per-UID isolation, work profiles) still runs inside the same kernel. A maliciously crafted file could exploit a parser vulnerability to reach the host OS.

With pKVM, the Microdroid guest runs under a **hardware hypervisor**. Even if the parser is completely compromised by a malicious input, the attack surface is:

```
Malicious JPEG
     │
     ▼  exploits a bug in the EXIF parser
  Guest VM kernel  ← attack is contained here
     │
     │  pKVM hardware boundary  ← cannot cross
     ▼
  Host Android OS  ← unaffected
```

---

## Architecture Inside the VM

```
AVmPayload_main()
      │
      ├─ socket(AF_VSOCK, SOCK_STREAM)
      ├─ bind(VMADDR_CID_ANY, port=5000)
      ├─ listen + accept  ← one connection per VM lifecycle
      │
      ▼
handle_connection(client_fd)
      │
      ├─ read [1-byte task type][4-byte BE length][N bytes of payload]
      │
      ├─ task 0: ScanFile(payload)                          (file_scan.cpp)
      ├─ task 2: StripFileScanMeta → ScanFile(file, name, mime)
      │      │
      │      ├─ ZIP-family (PK header, or an end-of-central-directory record in the tail):
      │      │      ScanZip → file_type zip | apk | ooxml
      │      │        → structure: EOCD/central-dir bounds, local-vs-central names,
      │      │          duplicates, overlapping entries, prepended/appended data
      │      │        → zip-slip names, zip-bomb declared ratios, encrypted entries
      │      │        → executable magic inside image/text-named entries
      │      │        → APK: signing scheme (v1/v2/v3), unsigned, debug cert,
      │      │          manifest permission heuristics, classes.dex header + entropy
      │      │        → OOXML: vbaProject.bin macros, ActiveX, external
      │      │          attachedTemplate/oleObject/frame/subDocument relationships
      │      ├─ JPEG: parse_exif + JPEG polyglot/scan-data checks
      │      │        (no EXIF is fine: {"file_type":"jpeg","exif":"none"})
      │      ├─ PDF:  ScanPdf → pdfid-style keyword counts over raw + inflated
      │      │        streams, #xx-obfuscated names, header offset, %%EOF,
      │      │        trailing data, startxref bounds
      │      ├─ everything else: signature list, packed ELF/PE
      │      │        → clean = {"file_type":"<detected>"|"unknown"} (fail-open)
      │      ├─ task 2 only: CheckDeclaredType(name, mime, detected type)
      │      │        → bidi-override names, .jpg.apk-style double extensions,
      │      │          extension/MIME vs content (media↔media mislabels allowed)
      │      └─ merges cheap_filter_flagged/cheap_filter_reason into the JSON
      │
      ├─ any other task type: {"error":"unknown task type"}
      │
      ├─ send [4-byte BE length][1-byte status][JSON bytes]
      │
      └─ close + exit  ← VM destroyed by host immediately after
```

`parse_exif(file_bytes)`:

```
├─ Verify JPEG magic: FF D8
├─ Scan segments → find APP1 + "Exif\0\0" header
├─ Parse TIFF header (II = LE, MM = BE)
├─ Walk IFD0 entry table (12 bytes/entry)
├─ Recurse → ExifSubIFD (tag 0x8769)
├─ Recurse → GPS IFD    (tag 0x8825)
└─ Serialize known tags → JSON object
```

---

## Wire Protocol

Matches `VmPayloadProtocol.kt` in `noxos-app` byte-for-byte. One payload binary, one vsock session, dispatched by a task-type byte:

```
Host → Guest
  ╔═════════╦══════════════════╦═══════════════════════╗
  ║ 1 byte  ║  4 bytes (BE)    ║  N bytes              ║
  ║ Task    ║  Payload length  ║  Task payload         ║
  ╚═════════╩══════════════════╩═══════════════════════╝

  Task 0 (file scan):            payload = raw file bytes (≤ 150 MiB)
  Task 2 (file scan + metadata): payload = [u16 BE name_len][name UTF-8 ≤ 1024]
                                           [u16 BE mime_len][mime ≤ 255][raw file bytes ≤ 150 MiB]

Guest → Host
  ╔══════════════════╦═════════╦═══════════════════════════════╗
  ║  4 bytes (BE)    ║ 1 byte  ║  M bytes (UTF-8 JSON)         ║
  ║  Payload length  ║ Status  ║  Metadata or error message    ║
  ╚══════════════════╩═════════╩═══════════════════════════════╝

Status:
  0x00  OK             see response shapes below
  0x01  PARSE_ERROR    malformed EXIF structure, e.g. {"error":"invalid APP1 segment length"}
  0x02  MALFORMED      {"error":"payload size out of range"} / {"error":"malformed file scan metadata"} / {"error":"unknown task type"}
```

**Status 0 responses** always carry `file_type` (`jpeg png gif webp pdf zip apk ooxml ole2 isobmff mp3 ogg wav rar 7z gzip elf pe dex unknown`), plus type-specific metadata:

```json
{"file_type":"jpeg","Make":"Google","Model":"Pixel 9",...}
{"file_type":"jpeg","exif":"none"}
{"file_type":"apk","zip_entries":181,"apk_signing":"v3","permission_strings":8,"high_risk_permissions":0}
{"file_type":"ooxml","zip_entries":12,"ooxml_macros":false,"ooxml_activex":0,"ooxml_embeddings":0,"ooxml_external_rels":1}
{"file_type":"pdf","pdf_version":"1.7","pdf_header_offset":0,"pdf_streams":75,...,"pdf_js":0,"pdf_openaction":1,...}
{"file_type":"unknown"}
```

When a check fires, the same object gains `"cheap_filter_flagged":true,"cheap_filter_reason":"..."`. Policy (user decision, 2026-09-29): **fail-open only for unsupported-but-sane files** (status 0, no flag); anything flagged, status 1/2, or a VM error/timeout is fail-closed. Adding `file_type` and metadata keys is backward compatible: `TriggerRouter` treats unknown status-0 keys as display metadata.

---

## Supported EXIF Tags

The parser recognizes ~40 standard IFD0, ExifSubIFD, and GPS IFD tags:

| Category | Tags |
|----------|------|
| **Camera** | Make, Model, Software, Orientation |
| **Date/Time** | DateTime, DateTimeOriginal, DateTimeDigitized |
| **Image** | PixelXDimension, PixelYDimension, ColorSpace |
| **Exposure** | ExposureMode, ShutterSpeedValue, ApertureValue, ExposureBiasValue, ISO |
| **Optics** | FocalLength, FocalLengthIn35mmFilm, LensMake, LensModel |
| **GPS** | GPSInfoIFDPointer (pointer; full GPS coord parsing is future work) |
| **Copyright** | Artist, Copyright |

---

## Build

The payload is a `cc_library_shared` compiled with Soong inside the AOSP source tree:

```bp
cc_library_shared {
    name: "noxos_payload_stub",
    srcs: [
        "payload_main.cpp",
        "exif_parser.cpp",
        "file_cheap_filter.cpp",
        "zip_scan.cpp",
    ],
    shared_libs: [
        "libvm_payload#current",
    ],
    static_libs: [
        "libz",
    ],
    sdk_version: "current",
}
```

The host app (`noxos-app`) bundles the compiled `.so` via `jni_libs` + `use_embedded_native_libs: true` in its Soong `android_app` module (the Gradle/jniLibs handoff is a Phase 2 integration task — see [`noxos-app`](https://github.com/parrothacker1/noxos-app)).

> **No CMakeLists.txt.** No standalone NDK/CMake build path is officially documented for Microdroid payloads. Only the Soong path is confirmed. Adding a CMakeLists would mean inventing an unsupported path.

---

## Status & Verification

| Item | State |
|------|-------|
| Entry point (`AVmPayload_main`) | ✅ Confirmed against AOSP docs |
| `vm_config.json` shape | ✅ Confirmed against `writeavfapp` guide |
| EXIF parser code | ✅ Written, unit-tested, fuzz-tested |
| Task-type dispatch (file scan only; task 1 network sample removed 2026-09-29) | ✅ Written, matches locked `VmPayloadProtocol` contract |
| File cheap filter (magic-header/polyglot + scan-data size sanity) | ✅ Written, unit-tested, fuzz-tested |
| ZIP/APK scanner (structure, zip-slip/bomb, encrypted entries, signing, permissions, DEX header) | ✅ Written, unit-tested, fuzz-tested, run over 17 real APKs |
| OOXML checks (macros, ActiveX, external template/oleObject relationships) | ✅ Written, unit-tested, fuzz-tested, run over 123 real Office files |
| PDF scanner (pdfid-style keywords incl. inflated streams, structure) | ✅ Written, unit-tested, fuzz-tested, run over 188 real PDFs |
| Declared-type checks (task 2 name/MIME vs content) | ✅ Written, unit-tested, fuzz-tested; app side not yet sending task 2 |
| Built inside real AOSP/Microdroid | ⏳ Phase 2 — needs EC2 + Cuttlefish |
| Protected VM (hardware pKVM) | ⏳ Needs Pixel 6+ hardware |
| Adversarial test suite (fuzz) | ✅ libFuzzer harnesses for all three parsers, CI-enforced |

---

## Testing & Fuzzing

Every parser that touches attacker-controlled bytes (EXIF, file cheap filter, ZIP/APK scanner) lives in its own zero-AOSP-dependency `.h`/`.cpp` pair — only `payload_main.cpp` touches vsock/`vm_payload` APIs. This split means all of them are testable with a plain `clang++`, no AOSP tree or Android SDK required:

```bash
clang++ -std=c++17 -g -fsanitize=address,undefined -o exif_test exif_parser.cpp test/exif_parser_test.cpp && ./exif_test
clang++ -std=c++17 -g -fsanitize=address,undefined -o file_cf_test file_cheap_filter.cpp test/file_cheap_filter_test.cpp && ./file_cf_test
clang++ -std=c++17 -g -fsanitize=address,undefined -o zip_scan_test zip_scan.cpp test/zip_scan_test.cpp -lz && ./zip_scan_test
clang++ -std=c++17 -g -fsanitize=address,undefined -o pdf_scan_test pdf_scan.cpp test/pdf_scan_test.cpp -lz && ./pdf_scan_test
clang++ -std=c++17 -g -fsanitize=address,undefined -o file_scan_test file_scan.cpp file_type.cpp zip_scan.cpp pdf_scan.cpp exif_parser.cpp file_cheap_filter.cpp test/file_scan_test.cpp -lz && ./file_scan_test
```

Each has a matching libFuzzer harness under `fuzz/`:

```bash
clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined -o exif_fuzzer exif_parser.cpp fuzz/exif_fuzzer.cpp
mkdir -p corpus && cp fuzz/seeds/* corpus/
./exif_fuzzer corpus -max_total_time=60

clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined -o file_cf_fuzzer file_cheap_filter.cpp fuzz/file_cheap_filter_fuzzer.cpp
./file_cf_fuzzer -max_total_time=60

clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -o zip_fuzzer zip_scan.cpp fuzz/zip_scan_fuzzer.cpp -lz
mkdir -p corpus_zip && cp fuzz/seeds_zip/* corpus_zip/
./zip_fuzzer corpus_zip -max_total_time=60

clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -o pdf_fuzzer pdf_scan.cpp fuzz/pdf_scan_fuzzer.cpp -lz
mkdir -p corpus_pdf && cp fuzz/seeds_pdf/* corpus_pdf/
./pdf_fuzzer corpus_pdf -max_total_time=60 -max_len=65536
```

**A real bug was found and fixed this way, not a hypothetical.** The original `tiff_len` computation trusted the JPEG APP1 segment's declared length (`seg_len`, attacker-controlled) without checking it against either a minimum (`seg_len < 8` underflows the `size_t` subtraction) or the actual buffer size (`pos + 2 + seg_len > size` — a segment can *declare* far more bytes than the file actually contains). A 12-byte crafted input (`FF D8 FF E1 00 2D 45 78 69 66 00 00`) reproducibly triggered a heap-buffer-overflow read under `-fsanitize=address` against the pre-fix parser — confirmed by extracting the old logic and running it standalone before the fix landed, not inferred. Fixed by validating `seg_len` against both bounds before trusting it; regression-tested in `test/exif_parser_test.cpp` and kept as a fuzz seed (`fuzz/seeds/regression_oob_seg_len.jpg`).

The file cheap-filter fuzzer found nothing in its first local runs (~3.7M executions, clean under ASan+UBSan), so it starts from an empty corpus.

The ZIP/APK scanner and the extended file filter each hit one real UBSan finding while fuzzing: `memmem()` was called with a null pointer when the input (or a decompressed v1 cert entry) was empty. Both calls now go through a null-safe `ContainsBytes()`, and the crashing ZIP is kept as `fuzz/seeds_zip/regression_empty_v1_cert.zip`. Clean runs after the fix: ~16.8M ZIP executions and ~4.7M file-filter executions, with `-fno-sanitize-recover=all`.

CI (`.github/workflows/ci.yml`) runs all self-check tests and a 60-second bounded fuzz pass per parser (all under ASan+UBSan) on every push/PR — a fixed time budget, not exhaustive, but enough to catch regressions.

---

<div align="center">
<sub>Part of <a href="https://github.com/parrothacker1/noxos">NoxOS</a></sub>
</div>
