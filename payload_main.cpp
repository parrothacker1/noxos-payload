// noxos-payload: microdroid VM payload stub
//
// Pre-Phase-2 scaffolding. Nothing in this file has been built or executed
// inside an actual Microdroid VM yet -- see README.md "Status" section.
//
// Entry point confirmed against AOSP docs as of 2026-08:
//   packages/modules/Virtualization/build/microdroid/README.md documents
//   a VM payload as a shared library exporting `AVmPayload_main`, declared
//   via <vm_payload/api.h>. The documented minimal example is literally:
//
//     extern "C" int AVmPayload_main() {
//       printf("Hello Microdroid!\n");
//     }
//
// This stub follows that shape and does nothing else. It is not the P6
// payload -- it only pins the entry point so the build plumbing (Android.bp,
// vm_config.json) has something real to compile/reference before Phase 2
// (validating Google's own unmodified reference demo) has actually run.
//
// P6 replaces this body with the real minimal custom payload.
// P7 adds the real untrusted-file parser + adversarial tests.
// Neither belongs here yet.

#include <vm_payload/api.h>

#include <cstdio>

extern "C" int AVmPayload_main() {
  std::printf("hello from microdroid, replace me in P6\n");
  return 0;
}
