# noxos-payload

Native isolated payload that runs inside the Microdroid pVM (`AVmPayload_main()`, file parsers) for NoxOS's untrusted-content isolation.

Kept as a separate repo deliberately: its commit history is the audit trail for everything that has ever executed inside the trust boundary.

Part of [NoxOS](https://github.com/parrothacker1/noxos).

## Status: unverified scaffolding, pre-Phase-2

This repo currently contains a skeleton, not a working payload. It has **not** been built or executed inside a real Microdroid VM. Nothing here should be trusted to actually work until Phase 2 (below) has been run for real.

The project roadmap splits this deliberately:

- **Phase 2 (P2)**: prove the AVF/Microdroid pipeline works at all, using Google's own official reference demo, unmodified, before writing any custom code.
- **Phase 6 (P6)**: write the actual minimal custom payload.
- **Phase 7 (P7)**: real untrusted-file parser + adversarial testing.

This commit is scaffolding for the eventual P6 payload -- it exists so the shape of the build is pinned down and documented ahead of time, not to jump ahead of P2.

## Research findings (as of 2026-08-14)

Checked against current AOSP documentation (`source.android.com/docs/core/virtualization`, `android.googlesource.com/platform/packages/modules/Virtualization`) before writing any code here.

**Entry point -- confirmed.** A Microdroid VM payload is a native shared library exporting `AVmPayload_main()`, declared via `<vm_payload/api.h>`. This is documented directly in `packages/modules/Virtualization/build/microdroid/README.md`, with the minimal example being literally:

```cpp
extern "C" int AVmPayload_main() {
  printf("Hello Microdroid!\n");
}
```

`payload_main.cpp` in this repo follows that shape exactly and does nothing beyond it.

**Build path -- Android.bp / Soong, confirmed as the documented path.** The same README shows the payload built as a `cc_library_shared` inside the AOSP source tree, then embedded into a hosting app via `jni_libs` + `use_embedded_native_libs: true` on an `android_app` Soong module. I found no official documentation describing a supported *standalone* NDK/CMake build path for the payload binary itself, despite Microdroid exposing a subset of stable NDK APIs to code running inside it. Those are related but different claims -- "the guest environment provides NDK-stable ABI" is not the same as "you can build the payload outside the AOSP tree with plain CMake." Because only the Soong path is actually documented, that's what this repo scaffolds (`Android.bp`). No `CMakeLists.txt` was added -- adding one would mean inventing a build path I could not confirm.

`shared_libs: ["libvm_payload#current"]` (the versioned-stable-library link line in `Android.bp`) was not shown in the trimmed README example but was found referenced in an actual AOSP build diff for a real payload module. Included on that basis, flagged as slightly less certain than the entry point itself.

This repo's `Android.bp` only declares the payload library (`noxos_payload_stub`), not an `android_app` wrapper -- packaging a payload into a hosting APK's `jni_libs` and `assets/` is the hosting app's job, which is `noxos-app` (a separate repo), not this one.

**`vm_config.json` -- confirmed shape, minimal example.** `source.android.com/docs/core/virtualization/writeavfapp` shows the VM config manifest as:

```json
{
  "os": { "name": "microdroid" },
  "task": {
    "type": "microdroid_launcher",
    "command": "MicrodroidTestNativeLib.so"
  }
}
```

i.e. `task.command` names the payload `.so` file. This repo's `vm_config.json` follows that shape, pointing at `noxos_payload_stub.so` (matching the Soong module name in `Android.bp` -- Soong does not auto-prefix `cc_library_shared` output filenames with `lib`, the output file matches the module name).

A hosting app loads this file via the Java API: `new VirtualMachineConfig.Builder(context, "assets/vm_config.json")`, i.e. it's expected to live at `assets/vm_config.json` inside the host APK. Whether any *additional* `AndroidManifest.xml` entry is required beyond that asset path was not something I could confirm from the docs fetched -- see "Open questions" below.

## Open questions / TODO for Phase 2

Documentation on this topic is scattered across several AOSP pages and some of it did not fully resolve in research for this scaffolding pass. Do not treat the below as settled:

- **Standalone NDK/CMake build path**: not documented anywhere found. If it turns out to exist, it may be a better fit for this repo (keeps the payload buildable without a full AOSP checkout). Needs checking directly against a real AOSP tree (`noxos-os`) in Phase 2.
- **`AndroidManifest.xml` requirements**: unclear whether the host app needs manifest entries beyond bundling `assets/vm_config.json`. Needs checking against the actual reference demo app's manifest.
- **Which reference demo is "the" canonical one**: research surfaced two different official demos that don't obviously agree on entry points --
  - `demo_native` / `vm_demo_native` in the Virtualization repo, which uses an `android_native_main(int, char**)` entry point and is explicitly scoped to *system-level* VMs, with a note pointing non-system use cases at the Java APIs instead.
  - The `writeavfapp` guide's Java-hosted-app + native-payload flow, which uses `AVmPayload_main()` and matches what NoxOS actually needs (an ordinary app launching a disposable VM, not a system component).

  NoxOS's use case (an app-triggered, ephemeral VM for untrusted content) matches the second one, which is why this repo scaffolds around `AVmPayload_main()`. But Phase 2 should explicitly build and run *both* Google demos unmodified on real infra to confirm this reading before any of P6 proceeds.
- **Test target**: `docs/getting_started.md` in the Virtualization repo confirms Cuttlefish is supported for AVF testing, but only for non-protected VMs ("Cuttlefish does not support protected VMs"). Protected-VM testing needs real Pixel hardware (6/6 Pro on Android 14+, 7/7 Pro, Fold, Tablet) with pKVM enabled via fastboot. Phase 2 should start on Cuttlefish (non-protected) since that's the lower-friction path, and note that protected-VM behavior is unverified until tested on real hardware.

## Files

- `payload_main.cpp` -- entry point stub, logs a placeholder message and returns. No parsing logic (that's P7).
- `Android.bp` -- Soong build module for the payload shared library, matching the documented AOSP build shape.
- `vm_config.json` -- placeholder VM config manifest describing the payload binary, matching the documented schema. Not yet wired into any hosting app.

## Next step

Phase 2: build and run Google's own unmodified reference demo(s) end-to-end (starting on Cuttlefish, non-protected), against a real `noxos-os` AOSP checkout, before treating anything in this repo as verified.
