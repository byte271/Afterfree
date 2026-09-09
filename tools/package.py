#!/usr/bin/env python3
"""Create a source-only release archive with an integrity manifest."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sources():
    files = set()
    for name in (
        "README.md",
        "spec.md",
        "VALIDATION.md",
        "OPTIMIZATION.md",
        "LICENSE",
        "pyproject.toml",
        "setup.py",
        ".gitignore",
        ".clang-format",
    ):
        path = ROOT / name
        if not path.is_file():
            raise RuntimeError(f"missing release document: {name}")
        files.add(path)
    for pattern in (
        "native/*.cpp",
        "native/*.c",
        "native/*.hpp",
        "native/*.h",
        "afterfree/*.py",
        "tests/*.py",
        "tests/*.c",
        "tests/*.S",
        "tools/*.py",
        "docs/**/*.md",
        "docs/evidence/*.json",
        "docs/evidence/*.xml",
        "docs/baselines/*.zip",
        ".github/workflows/*.yml",
    ):
        files.update(ROOT.glob(pattern))
    return sorted(files)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    files = sources()
    manifest = {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in files
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        args.output, "w", zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:

        def add(name, data, executable=False):
            info = zipfile.ZipInfo("afterfree/" + name, (2026, 9, 6, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100755 if executable else 0o100644) << 16
            archive.writestr(info, data)

        for path in files:
            name = str(path.relative_to(ROOT))
            add(name, path.read_bytes(), name.startswith("tools/"))
        add("SOURCE-MANIFEST.json", (json.dumps(manifest, indent=2) + "\n").encode())
    print(
        json.dumps(
            {
                "archive": str(args.output.resolve()),
                "source_files": len(files),
                "bytes": args.output.stat().st_size,
                "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
