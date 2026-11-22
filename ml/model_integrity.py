"""SHA-256 manifest for model files."""

import hashlib
import os
import sys
from pathlib import Path

MANIFEST = "MODEL_SHA256SUMS"
SUFFIXES = (".joblib", ".onnx", ".pt", ".txt")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(model_dir) -> Path:
    model_dir = Path(model_dir)
    lines = []
    for p in sorted(model_dir.iterdir()):
        if p.is_file() and p.suffix in SUFFIXES and p.name != MANIFEST:
            lines.append(f"{_sha256(p)}  {p.name}")
    out = model_dir / MANIFEST
    out.write_text("\n".join(lines) + "\n")
    return out


def verify_dir(model_dir) -> None:
    """Raise RuntimeError if the manifest is missing (when required) or a file differs."""
    model_dir = Path(model_dir)
    manifest = model_dir / MANIFEST
    if not manifest.exists():
        if os.environ.get("WIDPS_REQUIRE_MODEL_MANIFEST") == "1":
            raise RuntimeError(f"{manifest} missing and WIDPS_REQUIRE_MODEL_MANIFEST=1")
        sys.stderr.write(f"[integrity] WARNING: no {MANIFEST} in {model_dir}; model files are unverified\n")
        return
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        name = name.strip()
        path = model_dir / name
        if not path.exists():
            raise RuntimeError(f"model file listed in manifest is missing: {name}")
        if _sha256(path) != digest:
            raise RuntimeError(f"model file does not match manifest (possible tampering): {name}")
    sys.stderr.write(f"[integrity] {model_dir} verified against {MANIFEST}\n")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "write":
        print(write_manifest(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "verify":
        verify_dir(sys.argv[2])
        print("ok")
    else:
        print("usage: model_integrity.py write|verify <model_dir>")
        sys.exit(2)
