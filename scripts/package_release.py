#!/usr/bin/env python3
"""Build a tag-matched release bundle from an explicit public-file allowlist."""
import argparse
import hashlib
import io
import os
import json
import platform
from pathlib import Path
import re
import struct
import subprocess
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
TARGETS = [(os_name, arch) for os_name in ("linux", "darwin", "windows") for arch in ("amd64", "arm64")]
VERSION_RE = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$")
FIXED_FILES = ["README.md", "README.zh-CN.md", "LICENSE", "NOTICE", "CHANGELOG.md", "internal/version/VERSION",
               "configs/guiliu.example.json", "skills/guiliu-query/SKILL.md",
               "skills/guiliu-query/references/recipes.md", "skills/guiliu-query/references/semantics.md"]


def validate_tag(tag, root=ROOT):
    match = VERSION_RE.fullmatch(tag)
    if not match or (match[4] and any(x.isdigit() and len(x) > 1 and x[0] == "0" for x in match[4].split("."))):
        raise ValueError("tag must be v-prefixed SemVer, for example v0.3.3 or v0.3.3-rc.1")
    version = (root / "internal/version/VERSION").read_text().strip()
    if tag != "v" + version:
        raise ValueError(f"tag {tag} does not match source version {version}")
    return version


def payload_files(root=ROOT):
    # Never walk the workspace into a release. Local databases, credentials,
    # captures and dotfiles are excluded even if accidentally placed nearby.
    tracked = subprocess.check_output(["git", "ls-files", "-z", "--", "docs", "web/public/brand"], cwd=root).decode().split("\0")
    files = set(FIXED_FILES)
    files.update(p for p in tracked if p and (p.endswith(".md") or p.startswith("docs/images/") and p.endswith((".jpg", ".png")) or p.startswith("web/public/brand/") and p.endswith(".svg")))
    for name in sorted(files):
        path = root / name
        if path.is_symlink() or not path.is_file() or path.resolve() != root.resolve() / name:
            raise ValueError(f"missing or unsafe public release file: {name}")
        yield name, path.read_bytes(), 0o644


def validate_binary(data, goos, arch):
    expected = {"amd64": 62, "arm64": 183}
    if goos == "linux":
        valid = data[:6] == b"\x7fELF\x02\x01" and len(data) >= 20 and struct.unpack_from("<H", data, 18)[0] == expected[arch]
    elif goos == "darwin":
        valid = data[:4] == b"\xcf\xfa\xed\xfe" and len(data) >= 8 and struct.unpack_from("<I", data, 4)[0] == {"amd64": 0x1000007, "arm64": 0x100000c}[arch]
    else:
        valid = False
        if data[:2] == b"MZ" and len(data) >= 64:
            offset = struct.unpack_from("<I", data, 60)[0]
            valid = len(data) >= offset + 6 and data[offset:offset+4] == b"PE\0\0" and struct.unpack_from("<H", data, offset+4)[0] == {"amd64": 0x8664, "arm64": 0xaa64}[arch]
    if not valid:
        raise ValueError(f"executable header does not match {goos}/{arch}")


def bundle(binary, goos, arch, tag, output, root=ROOT):
    validate_tag(tag, root)
    if (goos, arch) not in TARGETS:
        raise ValueError("unsupported target")
    data = Path(binary).read_bytes()
    validate_binary(data, goos, arch)
    platform_name = "mac" if goos == "darwin" else goos
    name = f"guiliu-{platform_name}-{arch}-{tag}"
    executable = "gl-cli.exe" if goos == "windows" else "gl-cli"
    files = [(executable, data, 0o755), *payload_files(root)]
    output.mkdir(parents=True, exist_ok=True)
    archive = output / (name + (".zip" if goos == "windows" else ".tar.gz"))
    if goos == "windows":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for relative, content, mode in files:
                entry = zipfile.ZipInfo(f"{name}/{relative}")
                entry.create_system = 3
                entry.external_attr = (0o100000 | mode) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(entry, content)
    else:
        with tarfile.open(archive, "w:gz") as tf:
            for relative, content, mode in files:
                entry = tarfile.TarInfo(f"{name}/{relative}")
                entry.size, entry.mode, entry.mtime = len(content), mode, 0
                tf.addfile(entry, io.BytesIO(content))
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + ".sha256").write_text(f"{checksum}  {archive.name}\n")
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--goos", choices=["linux", "darwin", "windows"])
    parser.add_argument("--goarch", choices=["amd64", "arm64"])
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "bin/release")
    args = parser.parse_args()
    if args.all and (args.goos or args.goarch) or not args.all and not (args.goos and args.goarch):
        parser.error("choose --all or both --goos and --goarch")
    validate_tag(args.tag)
    subprocess.run(["node", "scripts/version.mjs", "check", args.tag[1:]], cwd=ROOT, check=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    # Local builds identify uncommitted source, rather than claiming a clean HEAD.
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT):
        commit += "-dirty"
    built = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ldflags = f"-s -w -X github.com/BaiLi-Labs/GuiLiu/internal/version.Commit={commit} -X github.com/BaiLi-Labs/GuiLiu/internal/version.BuildDate={built}"
    for goos, arch in TARGETS if args.all else [(args.goos, args.goarch)]:
        with tempfile.TemporaryDirectory(prefix="guiliu-build-") as work:
            binary = Path(work) / ("gl-cli.exe" if goos == "windows" else "gl-cli")
            print(f"Building {goos}/{arch}", flush=True)
            subprocess.run(["go", "build", "-p", "2", "-trimpath", "-ldflags", ldflags, "-o", str(binary), "./cmd/gl-cli"], cwd=ROOT, check=True,
                           env={**os.environ, "CGO_ENABLED":"0", "GOOS":goos, "GOARCH":arch, "GOMAXPROCS":"2"})
            native_os = {"Linux":"linux", "Darwin":"darwin", "Windows":"windows"}.get(platform.system())
            native_arch = {"x86_64":"amd64", "AMD64":"amd64", "arm64":"arm64", "aarch64":"arm64", "ARM64":"arm64"}.get(platform.machine())
            if (goos, arch) == (native_os, native_arch):
                info = subprocess.check_output([str(binary), "version"], cwd=work, text=True)
                if not info.startswith("gl-cli " + args.tag[1:] + " "):
                    raise ValueError("native executable version does not match tag")
                description = json.loads(subprocess.check_output([str(binary), "query", "describe"], cwd=work, text=True))
                if description["name"] != "gl-cli query" or description["version"] != args.tag[1:]:
                    raise ValueError("native query discovery contract does not match tag")
                print("Native version and offline query discovery passed", flush=True)
            print(bundle(binary, goos, arch, args.tag, args.output), flush=True)


if __name__ == "__main__":
    main()
