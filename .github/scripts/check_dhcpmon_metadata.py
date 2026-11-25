"""Compare DHCPMon's generated Debian metadata to the runtime and its target libraries."""

import argparse
from email.parser import Parser
import hashlib
import json
from pathlib import Path
import re
import tempfile

from check_dhcpmon_artifacts import build_id, copy_payload, readelf


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(arch, runtime, metadata, trees, debian):
    package = "sonic-dhcpmon"
    doc = json.loads(metadata.read_text())
    if (doc["schema"], doc["module"], doc["architecture"], set(doc["packages"])) != (1, package, arch, {package}):
        raise ValueError("wrong metadata schema, owner, architecture or package set")
    entry = doc["packages"][package]
    fields = entry["control_fields"]
    first = re.match(r"sonic-dhcpmon \(([^)]+)\)", (debian / "changelog").read_text())
    if not first:
        raise ValueError("cannot determine sonic-dhcpmon version from debian/changelog")
    version = first[1]
    if (fields["Package"], fields["Architecture"], fields["Version"]) != (package, arch, version):
        raise ValueError("package identity does not match the native architecture and source changelog")
    if entry["runtime_target"] != "//:runtime" or entry["payload_sha256"] != digest(runtime):
        raise ValueError("metadata describes a different runtime archive")
    if "usr/sbin/dhcpmon" not in entry.get("required_paths", []):
        raise ValueError("the metadata does not require the shipped daemon")
    for name in ("control", "changelog"):
        if doc["_generated"][name + "_sha256"] != digest(debian / name):
            raise ValueError(f"metadata does not match debian/{name}")
    if "${" in json.dumps(fields):
        raise ValueError("unresolved Debian control substitution")

    with tempfile.TemporaryDirectory() as work:
        binary = Path(work) / "dhcpmon"
        copy_payload(runtime, "usr/sbin/dhcpmon", 0o755, binary)
        identifier = build_id(binary, arch)
        needed = set(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", readelf("--dynamic", binary)))
    # Compare the actual SONAMEs to the target packages listed in the generated Depends.
    depends = set(re.findall(r"(?:^|[,|])\s*([a-z0-9][a-z0-9+.-]*)", fields["Depends"]))
    if "libpcap.so.0.8" not in needed:
        raise ValueError("runtime or metadata does not declare the Trixie packet capture library")
    providers = {name: set() for name in needed}
    for tree in trees:
        manifest = json.loads((tree / "manifest.json").read_text())
        if manifest["architecture"] != arch:
            raise ValueError("dependency tree architecture does not match the daemon")
        for record in manifest["packages"]:
            root = tree / record["root"]
            control = Parser().parsestr((root / "DEBIAN/control").read_text())
            if control["Package"] not in depends or control["Architecture"] not in (arch, "all"):
                continue
            for library in root.rglob("*.so*"):
                if library.name in needed and library.is_file():
                    providers[library.name].add(control["Package"])
    missing = sorted(name for name, owners in providers.items() if not owners)
    if missing:
        raise ValueError(f"no declared target package in Depends provides these runtime libraries: {missing}")
    if "libpcap0.8t64" not in providers["libpcap.so.0.8"]:
        raise ValueError("metadata does not use the Trixie libpcap0.8t64 provider")
    return {"architecture": arch, "build_id": identifier, "version": version,
            "payload_sha256": entry["payload_sha256"],
            "needed_providers": {n: sorted(providers[n]) for n in sorted(needed)}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("architecture", choices=("amd64", "arm64"))
    parser.add_argument("runtime", type=Path)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("package_trees", type=Path, help="one Bazel target package tree per line")
    args = parser.parse_args()
    trees = [Path(line) for line in args.package_trees.read_text().splitlines() if line]
    print(json.dumps(verify(args.architecture, args.runtime, args.metadata, trees, Path("debian")), indent=2))
