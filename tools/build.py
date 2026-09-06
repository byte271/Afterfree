#!/usr/bin/env python3
"""Build the native runtime with checksum-pinned upstream binary SDKs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
QBDI = {
    "url": "https://github.com/QBDI/QBDI/releases/download/v0.12.0/QBDI-0.12.0-ubuntu24.04-X86_64.tar.gz",
    "sha256": "b768d8feede1fe2da7cf41c436c03473007d8ddd7fcec54fe1eef9299ac1343b",
}
UNICORN = {
    "url": "https://files.pythonhosted.org/packages/e7/df/ded5e3684c2d7600b30cc8a7530277b8cb36644a1a9d34cade7ebb45604c/unicorn-2.1.4-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
    "sha256": "9d6e6dea140560de4ebd8446661f7ef84a357d428c14a3ef09dacd306ec8c239",
}
ZYDIS = {
    "url": "https://github.com/zyantific/zydis/releases/download/v4.1.0/zydis-amalgamated.tar.gz",
    "sha256": "aa9b82be3a37a2998bd8e16cf583bbf2b6c3d80e97dc20504169dc32ca1ced59",
}


def download(spec, path):
    if (
        path.exists()
        and hashlib.sha256(path.read_bytes()).hexdigest() == spec["sha256"]
    ):
        return
    print(f"Downloading {path.name}", flush=True)
    temp = path.with_suffix(".part")
    try:
        with urllib.request.urlopen(spec["url"], timeout=60) as source, temp.open(
            "wb"
        ) as dest:
            shutil.copyfileobj(source, dest)
        if hashlib.sha256(temp.read_bytes()).hexdigest() != spec["sha256"]:
            raise RuntimeError(f"checksum mismatch for {path.name}")
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cache", type=Path, default=ROOT / ".cache")
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        p.error("Linux x86-64 is required")
    for tool in [os.environ.get("CXX", "g++"), os.environ.get("CC", "gcc")]:
        if not shutil.which(tool):
            p.error(f"{tool} is missing; install build-essential and libssl-dev")
    cache = args.cache.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    download(QBDI, cache / "qbdi.tar.gz")
    download(UNICORN, cache / "unicorn.whl")
    download(ZYDIS, cache / "zydis-amalgamated.tar.gz")
    sdk, unicorn = cache / "qbdi", cache / "unicorn"
    sdk.mkdir(exist_ok=True)
    unicorn.mkdir(exist_ok=True)
    with tarfile.open(cache / "qbdi.tar.gz") as archive:
        archive.extractall(sdk, filter="data")
    with tarfile.open(cache / "zydis-amalgamated.tar.gz") as archive:
        archive.extractall(cache / "zydis", filter="data")
    zydis = cache / "zydis/amalgamated-dist"
    with zipfile.ZipFile(cache / "unicorn.whl") as archive:
        for name in archive.namelist():
            destination = (unicorn / name).resolve()
            if not destination.is_relative_to(unicorn):
                raise RuntimeError("unsafe wheel member")
        archive.extractall(unicorn)
    destination = ROOT / "afterfree" / "_native"
    with tempfile.TemporaryDirectory(
        prefix=".afterfree-build-", dir=ROOT / "afterfree"
    ) as stage:
        out = Path(stage) / "_native"
        out.mkdir()
        qlib = sdk / "usr/lib/x86_64-linux-gnu"
        ulib = unicorn / "unicorn/lib"
        shutil.copy2(qlib / "libQBDI.so", out)
        shutil.copy2(ulib / "libunicorn.so.2", out)
        cxx = os.environ.get("CXX", "g++")
        common = [
            cxx,
            "-std=c++17",
            "-O2",
            "-g" if args.debug else "-DNDEBUG",
            "-Wall",
            "-Wextra",
            "-Werror",
        ]
        jobs = [
            [
                os.environ.get("CC", "gcc"),
                "-O2",
                "-std=c11",
                "-fPIC",
                "-I" + str(zydis),
                "-DZYDIS_STATIC_BUILD",
                "-DZYCORE_STATIC_BUILD",
                "-c",
                str(zydis / "Zydis.c"),
                "-o",
                str(cache / "zydis.o"),
            ],
            common
            + [
                "-fPIC",
                "-shared",
                "-I" + str(sdk / "usr/include"),
                str(ROOT / "native/runtime.cpp"),
                str(ROOT / "native/unwind.cpp"),
                "-I" + str(zydis),
                "-DZYDIS_STATIC_BUILD",
                "-DZYCORE_STATIC_BUILD",
                str(cache / "zydis.o"),
                "-L" + str(qlib),
                "-lQBDI",
                "-lcrypto",
                "-Wl,-rpath,$ORIGIN",
                "-o",
                str(out / "libafterfree.so"),
            ],
            common
            + [
                "-I" + str(unicorn / "unicorn/include"),
                "-I" + str(zydis),
                "-DZYDIS_STATIC_BUILD",
                "-DZYCORE_STATIC_BUILD",
                str(ROOT / "native/worker.cpp"),
                str(cache / "zydis.o"),
                "-L" + str(ulib),
                "-l:libunicorn.so.2",
                "-lcrypto",
                "-Wl,-rpath,$ORIGIN",
                "-o",
                str(out / "afterfree-worker"),
            ],
            [
                os.environ.get("CC", "gcc"),
                "-O2",
                "-fPIC",
                "-shared",
                "-fno-tree-vectorize",
                "-fno-builtin",
                str(ROOT / "tests/producers.c"),
                str(ROOT / "tests/state.S"),
                "-o",
                str(out / "libafterfree-fixtures.so"),
            ],
            common
            + [
                "-fPIC",
                "-shared",
                "-I" + str(sdk / "usr/include"),
                str(ROOT / "native/preload.cpp"),
                "-I" + str(zydis),
                "-DZYDIS_STATIC_BUILD",
                "-DZYCORE_STATIC_BUILD",
                str(sdk / "usr/lib/libQBDIPreload.a"),
                "-L" + str(out),
                "-lafterfree",
                "-lQBDI",
                "-lcrypto",
                "-Wl,-rpath,$ORIGIN",
                "-o",
                str(out / "libafterfree-preload.so"),
            ],
            [
                os.environ.get("CC", "gcc"),
                "-O2",
                str(ROOT / "tests/holding.c"),
                "-L" + str(out),
                "-lafterfree-fixtures",
                "-Wl,-rpath,$ORIGIN",
                "-o",
                str(out / "afterfree-fixture"),
            ],
            [
                os.environ.get("CC", "gcc"),
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(ROOT / "native/launch.c"),
                "-o",
                str(out / "afterfree-measure-launch"),
            ],
            [
                os.environ.get("CC", "gcc"),
                "-O2",
                "-fno-tree-vectorize",
                str(ROOT / "tests/mixed.c"),
                "-o",
                str(out / "afterfree-edge-fixture"),
            ],
            [
                os.environ.get("CC", "gcc"),
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(ROOT / "tests/dynamic.c"),
                "-ldl",
                "-o",
                str(out / "afterfree-dynamic-fixture"),
            ],
            [
                os.environ.get("CC", "gcc"),
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(ROOT / "tests/allocators.c"),
                "-L" + str(out),
                "-lafterfree-fixtures",
                "-Wl,-rpath,$ORIGIN",
                "-o",
                str(out / "afterfree-allocator-fixture"),
            ],
            [
                os.environ.get("CC", "gcc"),
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(ROOT / "tests/signals.c"),
                "-L" + str(out),
                "-lafterfree-fixtures",
                "-Wl,-rpath,$ORIGIN",
                "-o",
                str(out / "afterfree-signal-fixture"),
            ],
            [
                os.environ.get("CC", "gcc"),
                "-O2",
                "-fno-tree-vectorize",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(ROOT / "tests/loops.c"),
                "-o",
                str(out / "afterfree-loop-fixture"),
            ],
            common
            + [str(ROOT / "native/launch.cpp"), "-o", str(out / "afterfree-run")],
            [
                os.environ.get("CC", "gcc"),
                "-O2",
                "-fno-tree-vectorize",
                "-fno-inline",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(ROOT / "tests/region_program.c"),
                "-o",
                str(out / "afterfree-region-fixture"),
            ],
            [
                os.environ.get("CC", "gcc"),
                "-O2",
                "-fno-tree-vectorize",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(ROOT / "tests/read_plans.c"),
                "-L" + str(out),
                "-lafterfree-fixtures",
                "-Wl,-rpath,$ORIGIN",
                "-o",
                str(out / "afterfree-read-fixture"),
            ],
        ]
        for command in jobs:
            subprocess.run(command, check=True)
        info = {
            "qbdi": QBDI,
            "unicorn": UNICORN,
            "zydis": ZYDIS,
            "compiler": subprocess.check_output(
                [cxx, "--version"], text=True
            ).splitlines()[0],
            "platform": platform.platform(),
        }
        (out / "build-info.json").write_text(json.dumps(info, indent=2) + "\n")
        # Compile the entire runtime before replacing a working installation.
        # A compiler failure must never leave mismatched protocol binaries behind.
        backup = Path(stage) / "previous"
        if destination.exists():
            destination.rename(backup)
        try:
            out.rename(destination)
        except BaseException:
            if backup.exists():
                backup.rename(destination)
            raise
    print("Built Afterfree. Run: python -m afterfree doctor", flush=True)


if __name__ == "__main__":
    main()
