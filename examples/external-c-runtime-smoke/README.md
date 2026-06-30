# External C Runtime Smoke

This example shows the current host-lane shape for calling the
`JinguiSSL-bridge` C ABI from an external C executable.

The important rule is that the C caller must enter through the Cangjie
runtime before calling `@C` exports from the Bridge dynamic library:

1. `CJ_MRT_CjRuntimeInit()`
2. `CJ_MRT_SetCommandLineArgs(argc, argv)`
3. `CJ_MRT_CjRuntimeStart(c_entry)`
4. inside `c_entry`: `dlopen`, `dlsym`, and Bridge C ABI calls

Direct naked `dlopen` followed by immediate Bridge symbol calls is not a
supported proof shape for this example.

## Scope

This is a macOS `aarch64` smoke for the current Cangjie `cjnative` runtime
layout. It does not prove Linux, OpenHarmony, HarmonyOS, Windows, hosted
package consumption, or cross-toolchain C embedding compatibility.

## Build And Run

Build the Bridge dynamic library first from the repository root:

```bash
cjpm build
```

Then compile this C smoke from this directory:

```bash
clang bridge_runtime_smoke.c \
  -L"${CANGJIE_HOME}/runtime/lib/darwin_aarch64_cjnative" \
  -lcangjie-runtime \
  -ldl \
  -Wl,-rpath,"${CANGJIE_HOME}/runtime/lib/darwin_aarch64_cjnative" \
  -o bridge_runtime_smoke
```

If `CANGJIE_HOME` is not exported, use the installed Cangjie version path.
For the local macOS Cangjie `1.1.0` framework install, that path is usually:

```bash
export CANGJIE_HOME=/Library/Frameworks/Cangjie/1.1.0
```

No Cangjie C header is required for this smoke; the runtime entry symbols are
declared directly in `bridge_runtime_smoke.c`.

Run from this directory:

```bash
./bridge_runtime_smoke
```

You can override the Bridge dylib path with:

```bash
JINGUISSL_BRIDGE_DYLIB=/absolute/path/to/libjinguissl_bridge.dylib ./bridge_runtime_smoke
```

## Expected Output

The smoke checks:

- `bridge_ffi_init(NULL, NULL)` returns `-1`
- `bridge_ffi_init` with a too-small output buffer returns `-2`
- `bridge_ffi_init` with enough capacity returns `0` and the Bridge FFI version
- the other nine current C ABI exports return `-1` for null-input calls

On success, the program exits with status `0`.
