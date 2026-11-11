#!/usr/bin/env python3
"""
MSDK 4.18 Mini 4K alias patcher (ARM64)

WHAT THIS DOES
--------------
DJI MSDK 4.18 has no Mini 4K entry in the three identity enums:

    ProductType:  WM161(76) = Mini 2, WM232(75), WM247(95)
    Model:        DJI_MINI_2, DJI_MINI_SE, MAVIC_MINI
    CameraType:   DJICameraTypeWM161(49), WM232(51), WM247(55)

The Mini 4K reports:
    - DroneType raw 107  -> no enum match -> None / unknown product
    - CameraType raw unknown (seen as OTHER / 255)
      -> no camera component -> Aircraft.getCamera() == null
      -> SDK consumers see no camera.

This patcher modifies the app's own libSdkyclx_clx.so at the
DexFileLoader::LoadV28 entry.  Before ART's OpenCommon() consumes the
decrypted runtime classes2.dex, the loader applies two size-preserving
DEX patches:

    1. DataOsdGetPushCommon$DroneType.find(int)
          if (i == 107) i = 63;       // WM161 = Mini 2 identity

    2. DataCameraGetPushStateInfo$CameraType.find(int)
          if (i == 255) i = 49;       // WM161 camera type
          ... fallback return DJICameraTypeWM161 for unknown raw types

It then rewrites the DEX SHA-1 and Adler-32 so ART accepts the buffer.

WHY A LOADER PATCH
------------------
The SDK classes are not in the APK's classes*.dex.  libSdkyclx_clx.so
decrypts a blob and calls ART's DexFileLoader::OpenCommon() on the
in-memory classes2.dex.  The reliable substitution point is the
LoadV28 entry, before OpenCommon.  Patching the APK DEX does nothing.

SAFETY GUARDS
-------------
The injected routine checks, at runtime:
    - classes2.dex size == 8,049,600
    - DroneType.find original prologue at 0x3d4274 == 62 00 86 66
    - CameraType.find original prologue at 0x369798 == 62 00 16 57
If any check fails it returns without writing anything.  The DEX
offsets and the combined checksum/signature are tied to the exact
MSDK 4.18 classes2.dex; a different SDK build is skipped, not corrupted.

SCOPE / LIMITS
--------------
- ARM64 only (this routine is AArch64).
- API 28+ (DexFileLoader::LoadV28; LoadV26 is not patched).
- The loader offsets below match the DJI MSDK 4.18 arm64 loader used
  here.  The patcher refuses if the patch site does not match; it
  never blindly writes.
- The result presents the aircraft as a Mini 2 (WM161).  MSDK 4.18
  has no Mini 4K feature set, so Mini 4K-specific capabilities are
  not exposed.

USE
---
    python3 patch_msdk_loader.py --explain

    # patch a loader directly
    python3 patch_msdk_loader.py --so libSdkyclx_clx.so \
        --out libSdkyclx_clx-patched.so

    # patch an APK (replaces lib/arm64-v8a/libSdkyclx_clx.so)
    python3 patch_msdk_loader.py --apk app.apk \
        --out app-patched.apk

    # optional signing (same cert required for in-place updates)
    python3 patch_msdk_loader.py --apk app.apk \
        --out app-patched.apk \
        --ks my.keystore --ks-alias mykey \
        --ks-pass pass:... --key-pass pass:...

The script does not contain or download any DJI binaries.  It only
transforms files you provide, on devices you own.
"""

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Loader layout (DJI MSDK 4.18, arm64)
# ---------------------------------------------------------------------------

PATCH_SITE = 0x2F630          # DexFileLoader::LoadV28, original: ldr x21,[x19]
CAVE = 0x2F7B4                # unused mem_loadDex_dvm body on ART 13
CAVE_LIMIT = 0x2F9D0          # next exported function; cave must stay below
ORIGINAL_LOAD = bytes.fromhex("750240f9")   # ldr x21,[x19]
BL_PATCH = bytes.fromhex("61000094")        # bl 0x2f7b4

# Assembled from cave_routine.S (see that file for the human-readable source).
# sha256(patch bytes) = 6d48f2eec19d2557f2cca25c005b7cb741be215363b1adc986b8c463adcb25f6
CAVE_HEX = """
750240f9a82240b909789a52490fa0721f01096b01050054a8524f91097542b9
4a0c8052cad0ac723f010a6b41040054a8a64d9108611e91090140b94a0c8052
cae2aa723f010a6b61030054a0524f9100d0099121030010c20780d223144038
03140038420400f1a1ffff54a0a64d9100601e9101040050420980d223144038
03140038420400f1a1ffff54a032009181050010820280d22314403803140038
420400f1a1ffff542915995269b5aa72a90a00b9c0035fd613006b0033050400
13053f00620059662101120235120e00460300027020319353000a0438040300
1103d802020128f362056566110500000000000000001300ff00330304001303
31006200e55621021201352114006200e5564600000170205e7830000a003800
07006200e556460000011100d801010128ed62000f5711000000000000000000
58f26ff904f1d22a374b4fae529b8e66078b4541
"""
CAVE_BYTES = bytes.fromhex("".join(CAVE_HEX.split()))
CAVE_SHA256 = "6d48f2eec19d2557f2cca25c005b7cb741be215363b1adc986b8c463adcb25f6"

# Documentation constants for --explain (not used to write the DEX).
DEX_SIZE = 8049600
DRONE_OFFSET = 0x3D4274
CAMERA_OFFSET = 0x369798
DRONE_PROLOGUE = "62 00 86 66"
CAMERA_PROLOGUE = "62 00 16 57"
DEX_SHA1 = "58f26ff904f1d22a374b4fae529b8e66078b4541"
DEX_ADLER32 = 0x55ABC8A9


def die(msg: str) -> "NoReturn":
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def explain() -> None:
    print(__doc__)
    print("Patch constants for the runtime classes2.dex:")
    print(f"  DEX size             {DEX_SIZE}")
    print(f"  DroneType.find       {DRONE_OFFSET:#x}  prologue {DRONE_PROLOGUE}")
    print(f"  CameraType.find      {CAMERA_OFFSET:#x}  prologue {CAMERA_PROLOGUE}")
    print(f"  Combined SHA-1       {DEX_SHA1}")
    print(f"  Combined Adler-32    {DEX_ADLER32:#010x}")
    print()
    print("Cave routine sha256:", CAVE_SHA256)
    print("Patch site:", hex(PATCH_SITE), "cave:", hex(CAVE), "cave bytes:", len(CAVE_BYTES))


def verify_loader(blob: bytes) -> str:
    """Check that this is the expected arm64 loader and return the patch-site state."""
    if len(blob) < CAVE + len(CAVE_BYTES):
        die("file is too small for the expected loader layout")
    if blob[:4] != b"\x7fELF":
        die("not an ELF file")
    if blob[4] != 2 or blob[5] != 1:
        die("not a 64-bit little-endian ELF")
    e_machine = struct.unpack_from("<H", blob, 18)[0]
    if e_machine != 183:
        die(f"not AArch64 (e_machine={e_machine})")
    if CAVE + len(CAVE_BYTES) > CAVE_LIMIT:
        die("cave routine does not fit before the next function")
    if len(CAVE_BYTES) != 340:
        die("internal cave size mismatch")

    site = blob[PATCH_SITE:PATCH_SITE + 4]
    if site == ORIGINAL_LOAD:
        return "original"
    if site == BL_PATCH:
        return "already patched"
    word = struct.unpack("<I", site)[0]
    if (word & 0xFC000000) == 0x94000000:
        # bl to somewhere else; decode target for the error.
        imm = word & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        target = PATCH_SITE + imm * 4
        die(f"patch site is an unexpected bl to {target:#x}")
    die(f"unexpected bytes at patch site: {site.hex()}")


def patch_loader(blob: bytes) -> tuple[bytes, str]:
    state = verify_loader(blob)
    out = bytearray(blob)
    out[PATCH_SITE:PATCH_SITE + 4] = BL_PATCH
    out[CAVE:CAVE + len(CAVE_BYTES)] = CAVE_BYTES
    return bytes(out), state


def patch_so(in_path: Path, out_path: Path) -> None:
    data = in_path.read_bytes()
    patched, state = patch_loader(data)
    out_path.write_bytes(patched)
    print(f"input : {in_path}  sha256={hashlib.sha256(data).hexdigest()}")
    print(f"site  : {state} at {PATCH_SITE:#x}")
    print(f"cave  : {CAVE:#x}  {len(CAVE_BYTES)} bytes  sha256={CAVE_SHA256}")
    print(f"output: {out_path}  sha256={hashlib.sha256(patched).hexdigest()}")


def find_tool(name: str, explicit: str | None) -> str | None:
    if explicit:
        return explicit
    env = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if env:
        bt = sorted(Path(env, "build-tools").glob("*")) if Path(env, "build-tools").exists() else []
        for d in reversed(bt):
            p = d / name
            if p.exists():
                return str(p)
    return shutil.which(name)


def patch_apk(in_path: Path, out_path: Path, lib_entry: str,
              ks: str | None, ks_alias: str | None, ks_pass: str | None,
              key_pass: str | None, apksigner_path: str | None,
              zipalign_path: str | None) -> None:
    if ks and not ks_alias:
        die("--ks requires --ks-alias")

    with zipfile.ZipFile(in_path) as zin:
        names = zin.namelist()
        if lib_entry not in names:
            die(f"{lib_entry} not found in APK")
        loader = zin.read(lib_entry)
        patched, state = patch_loader(loader)
        print(f"input : {in_path}")
        print(f"loader: {lib_entry}  sha256={hashlib.sha256(loader).hexdigest()}")
        print(f"site  : {state} at {PATCH_SITE:#x}")
        print(f"cave  : {CAVE:#x}  {len(CAVE_BYTES)} bytes")

        tmpdir = Path(tempfile.mkdtemp(prefix="msdkpatch-"))
        unsigned = tmpdir / "unsigned.apk"
        with zipfile.ZipFile(unsigned, "w") as zout:
            for info in zin.infolist():
                data = patched if info.filename == lib_entry else zin.read(info.filename)
                zi = zipfile.ZipInfo(info.filename, info.date_time)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                zi.internal_attr = info.internal_attr
                zi.create_system = info.create_system
                zi.comment = info.comment
                # Android R+ requires resources.arsc stored.
                if info.filename == "resources.arsc":
                    zi.compress_type = zipfile.ZIP_STORED
                zout.writestr(zi, data)

    aligned = tmpdir / "aligned.apk"
    zipalign = find_tool("zipalign", zipalign_path)
    if zipalign:
        subprocess.run([zipalign, "-p", "-f", "4", str(unsigned), str(aligned)], check=True)
    else:
        print("warning: zipalign not found; output may not be 4-byte aligned", file=sys.stderr)
        shutil.copyfile(unsigned, aligned)

    if ks:
        apksigner = find_tool("apksigner", apksigner_path)
        if not apksigner:
            die("apksigner not found; pass --apksigner or sign manually")
        cmd = [apksigner, "sign", "--ks", ks, "--ks-key-alias", ks_alias,
               "--out", str(out_path)]
        if ks_pass:
            cmd += ["--ks-pass", ks_pass]
        if key_pass:
            cmd += ["--key-pass", key_pass]
        cmd += [str(aligned)]
        subprocess.run(cmd, check=True)
        print(f"signed: {out_path}")
    else:
        shutil.copyfile(aligned, out_path)
        print(f"output: {out_path} (unsigned)")
        print("sign with the same certificate as the installed app, e.g.:")
        print(f"  apksigner sign --ks YOUR.keystore --ks-key-alias ALIAS --out {out_path} {out_path}")

    print(f"output sha256: {hashlib.sha256(Path(out_path).read_bytes()).hexdigest()}")
    shutil.rmtree(tmpdir, ignore_errors=True)


def main() -> None:
    p = argparse.ArgumentParser(
        description="Patch the DJI MSDK 4.18 arm64 loader so a Mini 4K is "
                    "presented as WM161 (Mini 2) and a camera component is created.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run with --explain for the full MSDK rationale.")
    p.add_argument("--explain", action="store_true", help="print the rationale and exit")
    p.add_argument("--so", type=Path, help="input libSdkyclx_clx.so")
    p.add_argument("--apk", type=Path, help="input APK")
    p.add_argument("--out", type=Path, help="output file")
    p.add_argument("--lib", default="lib/arm64-v8a/libSdkyclx_clx.so",
                   help="APK loader entry (default: arm64)")
    p.add_argument("--ks", help="keystore for apksigner")
    p.add_argument("--ks-alias", help="key alias")
    p.add_argument("--ks-pass", help="e.g. pass:secret")
    p.add_argument("--key-pass", help="e.g. pass:secret")
    p.add_argument("--apksigner", help="path to apksigner")
    p.add_argument("--zipalign", help="path to zipalign")
    args = p.parse_args()

    if args.explain:
        explain()
        return
    if bool(args.so) == bool(args.apk):
        p.error("give exactly one of --so or --apk")
    if not args.out:
        p.error("--out is required")

    if args.so:
        patch_so(args.so, args.out)
    else:
        patch_apk(args.apk, args.out, args.lib, args.ks, args.ks_alias,
                  args.ks_pass, args.key_pass, args.apksigner, args.zipalign)


if __name__ == "__main__":
    main()
