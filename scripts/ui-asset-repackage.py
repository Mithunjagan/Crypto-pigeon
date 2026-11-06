"""Replace only WebView UI assets in an existing APK; never compile native code.

The original APK is kept in the UI rollback directory. Android zip alignment and
signing are separate steps, using the same installed signing certificate.
"""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import argparse
import hashlib
import json

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument("original", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("--verify", action="store_true")
args = parser.parse_args()
prefix = "assets/ui/"


def entries(path):
    with ZipFile(path) as archive:
        return {info.filename: hashlib.sha256(archive.read(info)).hexdigest()
                for info in archive.infolist() if not info.is_dir()}


if not args.verify:
    if args.original.resolve() == args.output.resolve():
        raise SystemExit("Output must differ from original APK")
    assets = root / "apps/local-ui/dist"
    if not (assets / "index.html").is_file():
        raise SystemExit("Build the local UI first")
    with ZipFile(args.original) as original, ZipFile(args.output, "w") as output:
        for info in original.infolist():
            # zipfile omits the old APK signing block. Drop v1 signatures too.
            signature = info.filename.upper().startswith("META-INF/") and info.filename.upper().endswith((".RSA", ".DSA", ".EC", ".SF", "MANIFEST.MF"))
            if not info.filename.startswith(prefix) and not signature:
                output.writestr(info, original.read(info))
        for asset in sorted(assets.rglob("*")):
            if asset.is_file():
                output.write(asset, prefix + asset.relative_to(assets).as_posix(), compress_type=ZIP_DEFLATED)

before, after = entries(args.original), entries(args.output)
native_before = {k: v for k, v in before.items() if not k.startswith(prefix) and not k.startswith("META-INF/")}
native_after = {k: v for k, v in after.items() if not k.startswith(prefix) and not k.startswith("META-INF/")}
assert native_before == native_after, "Non-UI APK content changed"
assets = root / "apps/local-ui/dist"
expected = {prefix + p.relative_to(assets).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in assets.rglob("*") if p.is_file()}
actual = {k: v for k, v in after.items() if k.startswith(prefix)}
assert expected == actual, "APK UI differs from production dist"
report = {"unchanged_non_ui_entries": len(native_before), "ui_entries": len(actual),
          "apk_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
          "native_code_unchanged": True, "ui_matches_dist": True}
if args.verify:
    (root / "artifacts/ui-overhaul-apk-verification.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
