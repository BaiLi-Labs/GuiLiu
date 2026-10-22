#!/usr/bin/env python3
"""Verify the complete release set before publishing any release assets."""
import argparse
import hashlib
from pathlib import Path
from package_release import ROOT, TARGETS, validate_tag


def manifest(directory, tag):
    validate_tag(tag)
    expected = {f'guiliu-{"mac" if os == "darwin" else os}-{arch}-{tag}{".zip" if os == "windows" else ".tar.gz"}' for os, arch in TARGETS}
    actual = {p.name for p in directory.iterdir() if p.name.endswith((".tar.gz", ".zip"))}
    if actual != expected:
        raise ValueError(f"release requires exactly six target bundles; missing={sorted(expected-actual)}, unexpected={sorted(actual-expected)}")
    lines = []
    for name in sorted(expected):
        digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        line = f"{digest}  {name}\n"
        if (directory / (name + ".sha256")).read_text() != line:
            raise ValueError(f"checksum mismatch: {name}")
        lines.append(line)
    (directory / "SHA256SUMS").write_text("".join(lines))


def release_notes(tag):
    version = validate_tag(tag)
    lines = (ROOT / "CHANGELOG.md").read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line == f"## [{version}]" or line.startswith(f"## [{version}] - "))
    end = next((i for i in range(start+1, len(lines)) if lines[i].startswith("## [")), len(lines))
    return "\n".join(lines[start+1:end]).strip() + "\n"


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tag", required=True)
    p.add_argument("--directory", type=Path, required=True)
    p.add_argument("--notes", type=Path, required=True)
    args = p.parse_args()
    manifest(args.directory, args.tag)
    args.notes.write_text(release_notes(args.tag))
