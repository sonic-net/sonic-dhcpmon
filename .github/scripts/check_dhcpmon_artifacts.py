"""Verify the installed dhcpmon executable and its detached debug symbols."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import zlib


ELF_MACHINES = {"amd64": 62, "arm64": 183}  # EM_X86_64, EM_AARCH64


def copy_payload(archive_path, expected, mode, dest):
    """Read only the expected regular member into a caller-selected temporary path."""
    with tarfile.open(archive_path) as archive:
        payload = [m for m in archive if not m.isdir()]
        if len(payload) != 1 or PurePosixPath(payload[0].name) != PurePosixPath(expected):
            raise ValueError(f"{archive_path}: expected a single payload at {expected}")
        member = payload[0]
        if not member.isfile() or (member.uid, member.gid, member.mode) != (0, 0, mode):
            raise ValueError(f"{archive_path}: {expected} must be a root-owned regular file with mode {mode:04o}")
        with archive.extractfile(member) as src, dest.open("wb") as out:
            shutil.copyfileobj(src, out)


def readelf(option, path):
    return subprocess.check_output(["readelf", "--wide", option, path], text=True, stderr=subprocess.STDOUT,
                                   env={**os.environ, "LC_ALL": "C"})


def build_id(path, arch):
    with path.open("rb") as f:
        header = f.read(20)
    machine = int.from_bytes(header[18:20], "little")
    if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01" or machine != ELF_MACHINES[arch]:
        raise ValueError(f"{path.name}: expected a little-endian {arch} ELF64 file")
    ids = re.findall(r"Build ID: ([0-9a-f]+)", readelf("--notes", path))
    if len(ids) != 1:
        raise ValueError(f"{path.name}: expected exactly one GNU build ID")
    return ids[0]


def verify(runtime_tar, debug_tar, tmp, arch):
    installed = "usr/sbin/dhcpmon"
    binary = tmp / "dhcpmon"
    copy_payload(runtime_tar, installed, 0o755, binary)
    identifier = build_id(binary, arch)
    if not re.search(r"\(NEEDED\).*\[libpcap\.so\.0\.8\]", readelf("--dynamic", binary)):
        raise ValueError("runtime does not link the declared Trixie libpcap.so.0.8")
    debug_member = f"usr/lib/debug/.build-id/{identifier[:2]}/{identifier[2:]}.debug"
    symbols = tmp / "dhcpmon.debug"
    copy_payload(debug_tar, debug_member, 0o644, symbols)
    if build_id(symbols, arch) != identifier:
        raise ValueError("runtime and symbols have different GNU build IDs")
    dwarf = r"\]\s+\.debug_info\s+"
    if re.search(dwarf, readelf("--section-headers", binary)):
        raise ValueError("runtime executable still contains DWARF debug information")
    if not re.search(dwarf, readelf("--section-headers", symbols)):
        raise ValueError("detached symbols lack DWARF debug information")

    link = tmp / "debuglink"
    # The section contents are architecture-independent; also allow checking an ARM tar on x86.
    subprocess.run(["objcopy", "-I", "elf64-little", f"--dump-section=.gnu_debuglink={link}",
                    binary, tmp / "copy"], check=True)
    name = PurePosixPath(debug_member).name.encode() + b"\0"
    checksum = zlib.crc32(symbols.read_bytes())
    expected_link = name.ljust((len(name) + 3) & ~3, b"\0") + checksum.to_bytes(4, "little")
    if not link.is_file() or link.read_bytes() != expected_link:
        raise ValueError("runtime .gnu_debuglink does not match the shipped symbol filename and CRC")
    return {"runtime": installed, "debug_file": debug_member, "architecture": arch,
            "build_id": identifier, "debuglink_crc32": f"{checksum:08x}"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=ELF_MACHINES, required=True)
    parser.add_argument("runtime_tar", type=Path)
    parser.add_argument("debug_tar", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        print(json.dumps(verify(args.runtime_tar, args.debug_tar, Path(directory), args.arch), indent=2))
