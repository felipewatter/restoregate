"""Unittest suite intentionally uses synthetic data only (no external services)."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import warnings
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from restoregate.cli import main
from restoregate.core import analyze_archive
from restoregate.paths import validate_member_path
from restoregate.policy import Policy, PolicyError, load_policy
from restoregate.report import write_report


class ArchiveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def zip(self, files: dict[str, bytes], compression=zipfile.ZIP_DEFLATED):
        p = self.root / "backup.zip"
        with zipfile.ZipFile(p, "w", compression=compression) as z:
            for name, contents in files.items():
                z.writestr(name, contents)
        return p

    def tar(self, files: dict[str, bytes], mode="w"):
        suffix = ".tar.gz" if mode == "w:gz" else ".tar"
        p = self.root / ("backup" + suffix)
        with tarfile.open(p, mode) as t:
            for name, contents in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(contents)
                t.addfile(info, io.BytesIO(contents))
        return p

    def codes(self, path, policy=None, drill=False):
        return [x.code for x in analyze_archive(path, policy, drill=drill).findings]

    def test_zip_scan(self):
        report = analyze_archive(self.zip({"folder/a.txt": b"hello", "b.txt": b"world"}))
        self.assertTrue(report.ok)
        self.assertEqual(report.files_checked, 2)
        self.assertEqual(report.bytes_checked, 10)
        self.assertEqual(len(report.archive_sha256), 64)

    def test_zip_drill(self):
        report = analyze_archive(self.zip({"a.txt": b"A", "deep/b.txt": b"BB"}), drill=True)
        self.assertTrue(report.ok)
        self.assertEqual(report.restored_files, 2)
        self.assertEqual(report.restored_bytes, 3)

    def test_zip_explicit_dirs(self):
        report = analyze_archive(self.zip({"dir/": b"", "dir/a": b"A"}), drill=True)
        self.assertTrue(report.ok)
        self.assertEqual(report.directories_checked, 1)

    def test_tar_scan(self):
        report = analyze_archive(self.tar({"a": b"hello", "b/c": b"world"}))
        self.assertTrue(report.ok)
        self.assertEqual(report.files_checked, 2)
        self.assertEqual(report.format, "tar")

    def test_targz_drill(self):
        report = analyze_archive(self.tar({"a": b"hello", "b/c": b"world"}, "w:gz"), drill=True)
        self.assertTrue(report.ok)
        self.assertEqual(report.restored_files, 2)

    def test_empty_archive_default_fails(self):
        self.assertIn("FILE_COUNT", self.codes(self.zip({})))

    def test_empty_archive_with_policy(self):
        self.assertTrue(analyze_archive(self.zip({}), Policy(min_files=0)).ok)

    def test_traversal_rejected_zip(self):
        self.assertIn("UNSAFE_PATH", self.codes(self.zip({"../escape": b"x"}), drill=True))
        self.assertFalse((self.root.parent / "escape").exists())

    def test_traversal_rejected_tar(self):
        self.assertIn("UNSAFE_PATH", self.codes(self.tar({"../../escape": b"x"}), drill=True))

    def test_windows_backslash_rejected(self):
        self.assertIn("UNSAFE_PATH", self.codes(self.zip({"..\\evil.txt": b"x"})))

    def test_absolute_rejected(self):
        self.assertIn("UNSAFE_PATH", self.codes(self.zip({"/etc/evil": b"x"})))

    def test_drive_and_ads_rejected(self):
        self.assertIn("UNSAFE_PATH", self.codes(self.zip({"C:evil": b"x"})))
        self.assertIn("UNSAFE_PATH", self.codes(self.zip({"x.txt:stream": b"x"})))

    def test_dot_trailing_space_reserved(self):
        self.assertIn("UNSAFE_PATH", self.codes(self.zip({"con.txt": b"x"})))
        self.assertIn("UNSAFE_PATH", self.codes(self.zip({"foo. ": b"x"})))

    def test_casefold_collision(self):
        self.assertIn("PATH_COLLISION", self.codes(self.zip({"Readme": b"a", "README": b"b"})))

    def test_duplicates(self):
        p = self.root / "duplicate.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("file", b"a")
                z.writestr("file", b"b")
        self.assertIn("PATH_COLLISION", self.codes(p))

    def test_file_parent_conflict(self):
        self.assertIn("PATH_CONFLICT", self.codes(self.zip({"a": b"file", "a/b": b"child"})))

    def test_symlink_zip_rejected(self):
        p = self.root / "symbolic.zip"
        with zipfile.ZipFile(p, "w") as z:
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, b"/etc/passwd")
        self.assertIn("ARCHIVE_INVALID", self.codes(p))

    def test_symlink_tar_rejected(self):
        p = self.root / "link.tar"
        with tarfile.open(p, "w") as t:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../etc/passwd"
            t.addfile(info)
        self.assertIn("ARCHIVE_INVALID", self.codes(p))

    def test_tar_device_rejected(self):
        p = self.root / "device.tar"
        with tarfile.open(p, "w") as t:
            info = tarfile.TarInfo("device")
            info.type = tarfile.CHRTYPE
            t.addfile(info)
        self.assertIn("ARCHIVE_INVALID", self.codes(p))

    def test_ratio_limit(self):
        self.assertIn("RATIO_LIMIT", self.codes(self.zip({"huge": b"0" * 30000}), Policy(max_ratio=10)))

    def test_total_limit(self):
        self.assertIn("TOTAL_LIMIT", self.codes(self.zip({"a": b"abc", "b": b"def"}), Policy(max_total_bytes=5)))

    def test_file_limit(self):
        self.assertIn("FILE_LIMIT", self.codes(self.zip({"a": b"abcd"}), Policy(max_file_bytes=3)))

    def test_archive_limit(self):
        self.assertIn("ARCHIVE_LIMIT", self.codes(self.zip({"a": b"abc"}), Policy(max_archive_bytes=8)))

    def test_member_limit(self):
        self.assertIn("MEMBER_LIMIT", self.codes(self.zip({"a": b"a", "b": b"b"}), Policy(max_members=1)))

    def test_depth_limit(self):
        self.assertIn("DEPTH_LIMIT", self.codes(self.zip({"a/b/c": b"a"}), Policy(max_depth=2)))

    def test_required_paths(self):
        self.assertIn("REQUIRED_MISSING", self.codes(self.zip({"a": b"b"}), Policy(required_paths=("database.sql",))))

    def test_min_files(self):
        self.assertIn("FILE_COUNT", self.codes(self.zip({"a": b"b"}), Policy(min_files=2)))

    def test_stale_archive(self):
        p = self.zip({"a": b"hi"})
        old = time.time() - 3600 * 10
        os.utime(p, (old, old))
        self.assertIn("STALE_BACKUP", self.codes(p, Policy(max_age_hours=2)))

    def test_unknown_format(self):
        p = self.root / "notarchive.bin"
        p.write_bytes(b"foo")
        self.assertIn("ARCHIVE_INVALID", self.codes(p))

    def test_symlink_archive_input(self):
        p = self.zip({"a": b"x"})
        link = self.root / "link.zip"
        try:
            link.symlink_to(p)
        except (OSError, NotImplementedError):
            self.skipTest("OS does not permit creating symlinks")
        self.assertIn("INPUT_INVALID", self.codes(link))

    def test_missing_archive(self):
        self.assertIn("INPUT_INVALID", self.codes(self.root / "missing.zip"))

    def test_corrupt_zip_payload(self):
        p = self.zip({"payload": b"HELLO12345"}, zipfile.ZIP_STORED)
        contents = p.read_bytes()
        pos = contents.index(b"HELLO12345")
        p.write_bytes(contents[:pos] + b"X" + contents[pos + 1:])
        self.assertIn("PAYLOAD_INVALID", self.codes(p))

    def test_corrupted_tar(self):
        p = self.tar({"x": b"some value"})
        p.write_bytes(p.read_bytes()[:14])
        self.assertIn("ARCHIVE_INVALID", self.codes(p))

    def test_archive_change_between_hashes_is_detected(self):
        p = self.zip({"a": b"present"})
        with patch("restoregate.core._hash_archive", side_effect=["a" * 64, "b" * 64]):
            self.assertIn("SOURCE_CHANGED", self.codes(p))

    def test_temporary_drill_path_is_removed(self):
        original = tempfile.TemporaryDirectory
        created = []

        def tracked(*args, **kwargs):
            temp = original(*args, **kwargs)
            created.append(temp.name)
            return temp

        with patch("restoregate.core.tempfile.TemporaryDirectory", side_effect=tracked):
            report = analyze_archive(self.zip({"conf/app.json": b"{}"}), drill=True)
        self.assertTrue(report.ok)
        self.assertEqual(len(created), 1)
        self.assertFalse(Path(created[0]).exists())

    def test_tar_member_limit_enforced_without_eager_member_list(self):
        self.assertIn("MEMBER_LIMIT", self.codes(self.tar({"one": b"a", "two": b"b"}), Policy(max_members=1)))

    def test_unknown_zip_compression_fails_closed(self):
        p = self.zip({"payload": b"abc"}, zipfile.ZIP_STORED)
        data = bytearray(p.read_bytes())
        # Local file header compression method at offset 8; central-directory at offset +10.
        local = data.find(b"PK\x03\x04")
        central = data.find(b"PK\x01\x02")
        self.assertGreaterEqual(local, 0)
        self.assertGreaterEqual(central, 0)
        data[local + 8:local + 10] = (99).to_bytes(2, "little")
        data[central + 10:central + 12] = (99).to_bytes(2, "little")
        p.write_bytes(data)
        self.assertIn("PAYLOAD_INVALID", self.codes(p))

    def test_sarif_json(self):
        report = analyze_archive(self.zip({"../a": b"bad"}))
        data = json.loads(report.to_json())
        sarif = json.loads(report.to_sarif())
        self.assertEqual(data["schema_version"], "1.0")
        self.assertFalse(data["ok"])
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "UNSAFE_PATH")

    def test_cli_json_output(self):
        p = self.zip({"healthy": b"hello"})
        out = self.root / "evidence.json"
        sarif = self.root / "findings.sarif"
        self.assertEqual(main(["scan", str(p), "--json-out", str(out), "--sarif-out", str(sarif), "--format", "json"]), 0)
        self.assertTrue(json.loads(out.read_text())["ok"])
        self.assertEqual(json.loads(sarif.read_text())["runs"][0]["results"], [])

    def test_cli_fails_with_findings(self):
        self.assertEqual(main(["scan", str(self.zip({"../x": b"x"}))]), 1)

    def test_cli_invalid_policy_returns_two(self):
        p = self.root / "policy.json"
        p.write_text('{"max_members": false}')
        self.assertEqual(main(["scan", "anything", "--policy", str(p)]), 2)

    def test_cli_subprocess_module(self):
        p = self.zip({"ok": b"Y"})
        env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
        result = subprocess.run([sys.executable, "-m", "restoregate", "drill", str(p), "--format", "json"], capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["restored_files"], 1)

    def test_atomic_report_writer(self):
        f = self.root / "report.json"
        write_report(str(f), '{"ok":true}\n')
        self.assertEqual(f.read_text(), '{"ok":true}\n')


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "policy.json"

    def bad_policy(self, data):
        self.path.write_text(json.dumps(data))
        with self.assertRaises(PolicyError):
            load_policy(self.path)

    def test_default_policy(self):
        self.assertEqual(load_policy(None).max_members, 10000)

    def test_custom_policy(self):
        self.path.write_text('{"max_members": 7, "required_paths": ["a/b"]}')
        p = load_policy(self.path)
        self.assertEqual(p.max_members, 7)
        self.assertEqual(p.required_paths, ("a/b",))

    def test_unknown_rejected(self):
        self.bad_policy({"silent_disable_security": True})

    def test_bool_integer_rejected(self):
        self.bad_policy({"max_members": True})

    def test_negative_rejected(self):
        self.bad_policy({"max_file_bytes": -1})

    def test_zero_ratio_rejected(self):
        self.bad_policy({"max_ratio": 0})

    def test_bad_required_path_rejected(self):
        self.bad_policy({"required_paths": ["../escape"]})

    def test_required_path_wrong_type_rejected(self):
        self.bad_policy({"required_paths": "a"})

    def test_nonobject_rejected(self):
        self.bad_policy([1, 2, 3])

    def test_invalid_json_rejected(self):
        self.path.write_text('{')
        with self.assertRaises(PolicyError):
            load_policy(self.path)


class PathTest(unittest.TestCase):
    def test_good_paths(self):
        for p in ("data/x.sql", "unicódé/á.txt", "file", "a_b/C1-2.cfg"):
            self.assertIsNone(validate_member_path(p), p)

    def test_bad_paths(self):
        for p in ("", "/etc/passwd", "../a", "a//b", "a/./b", "a/../b", "..\\evil", "a:\\foo", "NUL.txt", "foo ", "bad\x00name", "a?b"):
            self.assertIsNotNone(validate_member_path(p), p)

    def test_non_nfc(self):
        self.assertIsNotNone(validate_member_path("e\u0301.txt"))


if __name__ == "__main__":
    unittest.main()
