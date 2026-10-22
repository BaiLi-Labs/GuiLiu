from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from package_release import ROOT, TARGETS, FIXED_FILES, bundle, payload_files, validate_binary, validate_tag
from release_manifest import manifest, release_notes


def header(goos, arch):
    if goos == 'linux':
        result = bytearray(64)
        result[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', result, 18, {'amd64':62, 'arm64':183}[arch])
    elif goos == 'darwin':
        result = bytearray(32)
        result[:4] = b'\xcf\xfa\xed\xfe'
        struct.pack_into('<I', result, 4, {'amd64':0x1000007, 'arm64':0x100000c}[arch])
    else:
        result = bytearray(128)
        result[:2] = b'MZ'
        struct.pack_into('<I', result, 60, 64)
        result[64:68] = b'PE\0\0'
        struct.pack_into('<H', result, 68, {'amd64':0x8664, 'arm64':0xaa64}[arch])
    return bytes(result)


class ReleaseTests(unittest.TestCase):
    def test_tag_requires_exact_source_version(self):
        version = (ROOT / 'internal/version/VERSION').read_text().strip()
        self.assertEqual(validate_tag('v'+version), version)
        for bad in ('main', 'v99.0.0', 'v0.3.3-01', 'v0.3.3;echo bad', 'v0.3.3/../../private'):
            with self.assertRaises(ValueError): validate_tag(bad)

    def test_bundles_have_exact_target_and_public_payload(self):
        tag = 'v'+(ROOT / 'internal/version/VERSION').read_text().strip()
        public = {p for p, _, _ in payload_files()}
        with tempfile.TemporaryDirectory() as work:
            directory = Path(work)
            # Workspace secrets adjacent to output never enter the payload.
            (directory / 'guiliu.json').write_text('synthetic-secret-do-not-package')
            (directory / 'capture.ndjson').write_text('synthetic-private-data')
            for goos, arch in TARGETS:
                binary = directory / 'binary'
                data = header(goos, arch)
                binary.write_bytes(data)
                archive = bundle(binary, goos, arch, tag, directory)
                executable = 'gl-cli.exe' if goos == 'windows' else 'gl-cli'
                if archive.suffix == '.zip':
                    with zipfile.ZipFile(archive) as zf:
                        names = zf.namelist()
                        read = zf.read
                        self.assertEqual(read(next(x for x in names if x.endswith('/'+executable))), data)
                else:
                    with tarfile.open(archive) as tf:
                        names = tf.getnames()
                        item = next(x for x in tf.getmembers() if x.name.endswith('/'+executable))
                        self.assertEqual(item.mode, 0o755)
                        self.assertEqual(tf.extractfile(item).read(), data)
                relative = {'/'.join(n.split('/')[1:]) for n in names}
                self.assertEqual(relative, public | {executable})
                self.assertNotIn('guiliu.json', relative)
                self.assertNotIn('capture.ndjson', relative)
                with self.assertRaises(ValueError): validate_binary(data, goos, 'amd64' if arch == 'arm64' else 'arm64')
            manifest(directory, tag)
            self.assertEqual(len((directory / 'SHA256SUMS').read_text().splitlines()), 6)
            self.assertTrue(release_notes(tag).strip())
            archive.write_bytes(b'tampered')
            with self.assertRaises(ValueError): manifest(directory, tag)

    def test_missing_target_blocks_manifest(self):
        tag = 'v'+(ROOT / 'internal/version/VERSION').read_text().strip()
        with tempfile.TemporaryDirectory() as work:
            with self.assertRaises(ValueError): manifest(Path(work), tag)

    def test_symlink_payload_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            for name in FIXED_FILES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('synthetic')
            (root / 'private.txt').write_text('synthetic')
            (root / 'README.zh-CN.md').unlink()
            (root / 'README.zh-CN.md').symlink_to(root / 'private.txt')
            with patch('package_release.subprocess.check_output', return_value=b''):
                with self.assertRaises(ValueError): list(payload_files(root))


if __name__ == '__main__': unittest.main()
