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
      ├─ task 0: handle_file_scan(payload)
      │      │
      │      ├─ ZIP/APK (PK header, or an end-of-central-directory record in the tail):
      │      │      ScanZip(payload)
      │      │        → structure: EOCD/central-dir bounds, local-vs-central names,
      │      │          duplicates, overlapping entries, prepended/appended data
      │      │        → zip-slip names, zip-bomb declared ratios
      │      │        → executable magic inside image/text-named entries
      │      │        → APK: signing scheme (v1/v2/v3), unsigned, debug cert,
      │      │          manifest permission heuristics, classes.dex header + entropy
      │      ├─ everything else:
      │      │      parse_exif(payload)  → see below
      │      │      CheckFileCheapFilter(payload)
      │      │        → JPEG: magic-header/polyglot mismatch, scan-data size sanity
      │      │        → non-JPEG: signature list, packed ELF/PE (UPX marker, entropy)
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

  Task 0 (file scan):     payload = raw file bytes

Guest → Host
  ╔══════════════════╦═════════╦═══════════════════════════════╗
  ║  4 bytes (BE)    ║ 1 byte  ║  M bytes (UTF-8 JSON)         ║
  ║  Payload length  ║ Status  ║  Metadata or error message    ║
  ╚══════════════════╩═════════╩═══════════════════════════════╝

Status:
  0x00  OK             see per-task response shape below
  0x01  PARSE_ERROR    {"error":"no EXIF APP1 segment found in JPEG"}
  0x02  MALFORMED      {"error":"not a JPEG file"}
```

**Task 0 response, status 0** — EXIF fields as before, plus two additive/optional keys when `CheckFileCheapFilter` flags the file:

```json
{"Make":"Google","Model":"Pixel 9",...,"cheap_filter_flagged":true,"cheap_filter_reason":"embedded ZIP local file header signature 0 bytes after JPEG EOI marker"}
```

ZIP/APK responses are also status 0, with metadata instead of EXIF fields:

```json
{"file_type":"apk","zip_entries":181,"apk_signing":"v3","permission_strings":8,"high_risk_permissions":0}
```

A non-JPEG, non-ZIP file that trips the signature/packed-executable checks comes back as status 0 `{"cheap_filter_flagged":true,...}` instead of the old status 2 `not a JPEG file`, so the reason reaches the app. Clean non-JPEG files still get status 2.

Their absence means clean — `noxos-app`'s `TriggerRouter` reads `cheap_filter_flagged` with a `false` default, so a response with neither key is unambiguous and backward compatible.


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
| ZIP/APK scanner (structure, zip-slip/bomb, signing, permissions, DEX header) | ✅ Written, unit-tested, fuzz-tested, run over 17 real APKs |
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
```

**A real bug was found and fixed this way, not a hypothetical.** The original `tiff_len` computation trusted the JPEG APP1 segment's declared length (`seg_len`, attacker-controlled) without checking it against either a minimum (`seg_len < 8` underflows the `size_t` subtraction) or the actual buffer size (`pos + 2 + seg_len > size` — a segment can *declare* far more bytes than the file actually contains). A 12-byte crafted input (`FF D8 FF E1 00 2D 45 78 69 66 00 00`) reproducibly triggered a heap-buffer-overflow read under `-fsanitize=address` against the pre-fix parser — confirmed by extracting the old logic and running it standalone before the fix landed, not inferred. Fixed by validating `seg_len` against both bounds before trusting it; regression-tested in `test/exif_parser_test.cpp` and kept as a fuzz seed (`fuzz/seeds/regression_oob_seg_len.jpg`).

The file cheap-filter fuzzer found nothing in its first local runs (~3.7M executions, clean under ASan+UBSan), so it starts from an empty corpus.

The ZIP/APK scanner and the extended file filter each hit one real UBSan finding while fuzzing: `memmem()` was called with a null pointer when the input (or a decompressed v1 cert entry) was empty. Both calls now go through a null-safe `ContainsBytes()`, and the crashing ZIP is kept as `fuzz/seeds_zip/regression_empty_v1_cert.zip`. Clean runs after the fix: ~16.8M ZIP executions and ~4.7M file-filter executions, with `-fno-sanitize-recover=all`.

CI (`.github/workflows/ci.yml`) runs all three self-check tests and a 60-second bounded fuzz pass per parser (all under ASan+UBSan) on every push/PR — a fixed time budget, not exhaustive, but enough to catch regressions.

---

<div align="center">
<sub>Part of <a href="https://github.com/parrothacker1/noxos">NoxOS</a></sub>
</div>
