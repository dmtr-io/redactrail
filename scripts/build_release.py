"""Собрать архив релиза: только отслеживаемые git файлы, без state/audit/policy.json.

    python scripts/build_release.py
    python scripts/build_release.py --version 0.1.0 --out dist

Архив ложится в `dist/redactrail-<версия>.zip`, рядом — `SHA256SUMS`.
Установщик `install.ps1` качает именно эти файлы из GitHub Release.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from redactrail import __version__  # noqa: E402

FORBIDDEN_PARTS = ("/state/", "/audit/", "/tmp/", "/.git/", "/dist/", "/__pycache__/")
REQUIRED = ("install.ps1", "uninstall.ps1", "policy.example.json", "redactrail/app.py")


def build(out_dir: Path, version: str, ref: str = "HEAD") -> Path:
    """Собрать zip и проверить, что в него не попали лишние файлы."""
    out_dir.mkdir(parents=True, exist_ok=True)
    archive = out_dir / f"redactrail-{version}.zip"
    prefix = f"redactrail-{version}/"
    result = subprocess.run(
        ["git", "archive", "--format=zip", f"--prefix={prefix}", "-o", str(archive), ref],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git archive завершился с ошибкой")

    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
    forbidden = [
        name
        for name in names
        if any(part in name for part in FORBIDDEN_PARTS) or name.endswith("/policy.json")
    ]
    if forbidden:
        archive.unlink(missing_ok=True)
        raise RuntimeError(f"в архив попали лишние файлы: {forbidden[:5]}")
    missing = [suffix for suffix in REQUIRED if prefix + suffix not in names]
    if missing:
        archive.unlink(missing_ok=True)
        raise RuntimeError(f"в архиве нет обязательных файлов: {missing}")
    return archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Собрать архив релиза redactrail")
    parser.add_argument("--out", default=str(ROOT / "dist"))
    parser.add_argument("--version", default=__version__)
    parser.add_argument("--ref", default="HEAD")
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    try:
        archive = build(out_dir, args.version, args.ref)
    except RuntimeError as error:
        print(f"ошибка: {error}", file=sys.stderr)
        return 1

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (out_dir / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    print(f"архив: {archive}")
    print(f"размер: {archive.stat().st_size} байт")
    print(f"sha256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
