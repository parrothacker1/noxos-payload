<div align="center">

<img src="https://raw.githubusercontent.com/parrothacker1/noxos/main/assets/branding/logo-mark.svg" width="80" height="80" alt="NoxOS Logo">

# noxos-payload

**Native EXIF parser running inside the Microdroid guest VM**

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
handle_scan(client_fd)
      │
      ├─ read [4-byte BE length] + [N bytes of file data]
      │
      ├─ parse_exif(file_bytes)
      │      │
      │      ├─ Verify JPEG magic: FF D8
      │      ├─ Scan segments → find APP1 + "Exif\0\0" header
      │      ├─ Parse TIFF header (II = LE, MM = BE)
      │      ├─ Walk IFD0 entry table (12 bytes/entry)
      │      ├─ Recurse → ExifSubIFD (tag 0x8769)
      │      ├─ Recurse → GPS IFD    (tag 0x8825)
      │      └─ Serialize known tags → JSON object
      │
      ├─ send [4-byte BE length][1-byte status][JSON bytes]
      │
      └─ close + exit  ← VM destroyed by host immediately after
```

---

## Wire Protocol

Matches `VmPayloadProtocol.kt` in `noxos-app` byte-for-byte:

```
Host → Guest
  ╔══════════════════╦═══════════════════════╗
  ║  4 bytes (BE)    ║  N bytes              ║
  ║  File length     ║  Raw JPEG bytes       ║
  ╚══════════════════╩═══════════════════════╝

Guest → Host
  ╔══════════════════╦═════════╦═══════════════════════════════╗
  ║  4 bytes (BE)    ║ 1 byte  ║  M bytes (UTF-8 JSON)         ║
  ║  Payload length  ║ Status  ║  Metadata or error message    ║
  ╚══════════════════╩═════════╩═══════════════════════════════╝

Status:
  0x00  OK             {"Make":"Google","Model":"Pixel 9","DateTime":"2024:01:15 10:30:00",...}
  0x01  PARSE_ERROR    {"error":"no EXIF APP1 segment found in JPEG"}
  0x02  MALFORMED      {"error":"not a JPEG file"}
```

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
    srcs: ["payload_main.cpp"],
    shared_libs: [
        "libvm_payload#current",
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
| EXIF parser code | ✅ Written, uncommitted, awaiting Phase 2 build |
| Built inside real AOSP/Microdroid | ⏳ Phase 2 — needs EC2 + Cuttlefish |
| Protected VM (hardware pKVM) | ⏳ Needs Pixel 6+ hardware |
| Adversarial test suite (fuzz) | ⏳ Phase 7 |

---

<div align="center">
<sub>Part of <a href="https://github.com/parrothacker1/noxos">NoxOS</a></sub>
</div>
