# MSDK 4.18 Mini 4K alias patch

`patch_msdk_loader.py` patches the arm64 `libSdkyclx_clx.so` from DJI MSDK 4.18
so the SDK treats a Mini 4K as a Mini 2 (WM161) and exposes a camera component.

## Why the loader

The MSDK classes are not in the APK's `classes*.dex`. `libSdkyclx_clx.so`
decrypts the SDK DEX at runtime and hands it to ART. Editing DEX files inside
the APK has no effect.

The patch redirects `DexFileLoader::LoadV28` to a code cave that edits the
decrypted `classes2.dex` buffer before `OpenCommon()` parses it.

## What it changes

Two size-preserving DEX patches:

| Method | Original | Patched |
|---|---|---|
| `DataOsdGetPushCommon$DroneType.find(I)` | raw `107` matches no enum | `107 -> WM161 (63)` |
| `DataCameraGetPushStateInfo$CameraType.find(I)` | raw `255`/unknown resolves to `OTHER` | `255 -> DJICameraTypeWM161 (49)`, WM161 fallback |

The cave also recomputes the DEX SHA-1 and Adler-32.

`DroneType` WM161 makes ProductType, Model and PlatformType follow. CameraType
WM161 makes `camera.nhf` create a camera component, so
`BaseProduct.updateCamera()` keeps `ComponentKey.CAMERA` and
`Aircraft.getCamera()` returns a camera instead of `null`.

## Patch site

- `0x2f630`: `ldr x21,[x19]` -> `bl 0x2f7b4`
- `0x2f7b4`: 340-byte cave in the unused `mem_loadDex_dvm` body

Runtime guards:

- `classes2.dex` size `8,049,600`
- `DroneType.find` prologue at `0x3d4274`: `62 00 86 66`
- `CameraType.find` prologue at `0x369798`: `62 00 16 57`

If any guard fails, the routine returns without writing.

## Usage

```bash
python3 patch_msdk_loader.py --explain

# patch the loader directly
python3 patch_msdk_loader.py --so libSdkyclx_clx.so \
    --out libSdkyclx_clx-patched.so

# patch an APK
python3 patch_msdk_loader.py --apk app.apk \
    --out app-patched.apk

# patch and sign
python3 patch_msdk_loader.py --apk app.apk \
    --out app-patched.apk \
    --ks my.keystore --ks-alias mykey \
    --ks-pass pass:... --key-pass pass:...
```

`--apk` replaces `lib/arm64-v8a/libSdkyclx_clx.so`, stores `resources.arsc`,
runs `zipalign -p -f 4`, and signs with `apksigner` when a keystore is given.
For an in-place update, use the same certificate as the installed app.

Requires Python 3.10+. `zipalign` and `apksigner` are optional for unsigned
loader-only output.

## Verification

From a device with RC and aircraft connected:

```text
Aircraft.getCamera() = dji.internal.camera.fdd
getCameras().size()  = 1
cameraType0          = DJICameraTypeWM161 (49)
product              = DJI_MINI_2, raw 107, enum WM161
```

Reference MSDK 4.18 arm64 loader:

```text
input   eb0d5dba48660bd3518c1f8fcc8c00470168f8e47b91fae190586bd309dafc62
output  4de9c2476aabac6a1e91b893e5fdb2fea33df2363a94782d8f6ce32635b2ae4b
```

## Limits

- ARM64 only, API 28+ (`LoadV28`). `LoadV26` is not patched.
- Offsets target the MSDK 4.18 arm64 loader. The script refuses if the patch
  site does not match; the runtime cave skips any DEX that does not match.
- The aircraft is presented as a Mini 2. MSDK 4.18 has no Mini 4K feature set,
  so Mini 4K-specific capabilities are not exposed.
- No firmware or SDK blob is modified.
