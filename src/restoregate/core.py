"""Bounded, non-executing ZIP/TAR inspection and isolated restore drills."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import stat
import tarfile
import tempfile
import time
from typing import BinaryIO
import zipfile

from .paths import validate_member_path
from .policy import Policy
from .report import Report

CHUNK = 64 * 1024


class ArchiveReadError(Exception):
    pass


@dataclass(frozen=True)
class Member:
    name: str
    size: int
    directory: bool
    origin: object


def _hash_archive(path: Path, limit: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while block := stream.read(CHUNK):
            total += len(block)
            if total > limit:
                raise ArchiveReadError("Archive exceeds max_archive_bytes")
            digest.update(block)
    return digest.hexdigest()


def _members(handle: zipfile.ZipFile | tarfile.TarFile, kind: str, max_members: int) -> list[Member]:
    members: list[Member] = []
    if kind == "zip":
        # The ZIP parser indexes the central directory itself; avoid further
        # member work after the configured count has been exceeded.
        for item in handle.infolist()[: max_members + 1]:
            mode = (item.external_attr >> 16) & 0xFFFF
            if stat.S_IFMT(mode) not in (0, stat.S_IFDIR, stat.S_IFREG):
                raise ArchiveReadError(f"Unsupported ZIP member type: {item.filename}")
            if item.flag_bits & 1:
                raise ArchiveReadError(f"Encrypted ZIP member unsupported: {item.filename}")
            is_dir = item.is_dir()
            if stat.S_IFMT(mode) == stat.S_IFDIR and not is_dir:
                raise ArchiveReadError(f"Directory mode/file path mismatch: {item.filename}")
            members.append(Member(item.filename.rstrip("/") if is_dir else item.filename, item.file_size, is_dir, item))
    else:
        # Iterate TAR headers lazily; never call getmembers() on an untrusted archive.
        for item in handle:
            if len(members) >= max_members:
                return members + [Member("_limit_exceeded_", 0, False, None)]
            if not (item.isfile() or item.isdir()):
                raise ArchiveReadError(f"Unsupported TAR member (link/device/etc.): {item.name}")
            members.append(Member(item.name.rstrip("/") if item.isdir() else item.name, item.size, item.isdir(), item))
    return members


def _read_member(handle: zipfile.ZipFile | tarfile.TarFile, kind: str, member: Member) -> BinaryIO:
    if kind == "zip":
        return handle.open(member.origin)  # type: ignore[arg-type]
    stream = handle.extractfile(member.origin)  # type: ignore[arg-type]
    if stream is None:
        raise ArchiveReadError(f"Cannot read member: {member.name}")
    return stream


def _copy_checked(stream: BinaryIO, declared: int, max_file: int, budget: int, sink: BinaryIO | None = None) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while block := stream.read(CHUNK):
        total += len(block)
        if total > declared or total > max_file or total > budget:
            raise ArchiveReadError("Payload exceeded declared size or policy bounds")
        digest.update(block)
        if sink:
            sink.write(block)
    if total != declared:
        raise ArchiveReadError(f"Size mismatch: expected {declared}, read {total}")
    return digest.hexdigest(), total


def _open_archive(path: Path) -> tuple[zipfile.ZipFile | tarfile.TarFile, str]:
    if zipfile.is_zipfile(path):
        return zipfile.ZipFile(path, "r"), "zip"
    try:
        return tarfile.open(path, mode="r:*"), "tar"
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ArchiveReadError("Unsupported or corrupt archive (supported: ZIP, TAR, TAR.GZ, TAR.BZ2, TAR.XZ)") from exc


def _validate_metadata(items: list[Member], kind: str, policy: Policy, report: Report) -> list[Member]:
    seen: dict[str, Member] = {}
    all_files: set[str] = set()
    safe: list[Member] = []
    total_declared = 0
    if len(items) > policy.max_members:
        report.add("MEMBER_LIMIT", f"{len(items)} members exceed max_members={policy.max_members}")
        return []
    for item in items:
        reason = validate_member_path(item.name)
        if reason:
            report.add("UNSAFE_PATH", reason, item.name)
            continue
        if len(item.name.split("/")) > policy.max_depth:
            report.add("DEPTH_LIMIT", f"Path exceeds max_depth={policy.max_depth}", item.name)
            continue
        key = item.name.casefold()
        if key in seen:
            report.add("PATH_COLLISION", f"Duplicate/case-insensitive collision with {seen[key].name}", item.name)
            continue
        seen[key] = item
        if item.size < 0 or (item.directory and item.size != 0):
            report.add("INVALID_SIZE", "Negative size or nonempty directory", item.name)
            continue
        if not item.directory:
            all_files.add(key)
            total_declared += item.size
            if item.size > policy.max_file_bytes:
                report.add("FILE_LIMIT", f"Member size {item.size} exceeds max_file_bytes", item.name)
            if kind == "zip":
                z = item.origin
                ratio = item.size / max(1, z.compress_size)  # type: ignore[attr-defined]
                if ratio > policy.max_ratio:
                    report.add("RATIO_LIMIT", f"Compression ratio {ratio:.1f} exceeds max_ratio", item.name)
        safe.append(item)
    if total_declared > policy.max_total_bytes:
        report.add("TOTAL_LIMIT", f"Declared {total_declared} bytes exceed max_total_bytes={policy.max_total_bytes}")
    for item in safe:
        segments = item.name.split("/")
        for index in range(1, len(segments)):
            parent = "/".join(segments[:index]).casefold()
            if parent in all_files:
                report.add("PATH_CONFLICT", "A file is also used as a parent directory", item.name)
                break
    paths = {item.name for item in safe if not item.directory}
    for required in policy.required_paths:
        if required not in paths:
            report.add("REQUIRED_MISSING", "Required file missing from archive", required)
    files = sum(not item.directory for item in safe)
    if files < policy.min_files:
        report.add("FILE_COUNT", f"Found {files} files; expected at least {policy.min_files}")
    return safe


def _verify_unchanged(path: Path, policy: Policy, report: Report) -> None:
    if report.archive_sha256 is not None and _hash_archive(path, policy.max_archive_bytes) != report.archive_sha256:
        report.add("SOURCE_CHANGED", "Archive contents changed during verification")


def analyze_archive(archive: str | Path, policy: Policy | None = None, drill: bool = False) -> Report:
    policy = policy or Policy()
    path = Path(archive)
    report = Report(str(path), "drill" if drill else "scan", policy=policy.as_dict())
    try:
        if not path.is_file() or path.is_symlink():
            report.add("INPUT_INVALID", "Archive must be a regular non-symlink file")
            return report
        size = path.stat().st_size
        if size > policy.max_archive_bytes:
            report.add("ARCHIVE_LIMIT", f"Archive has {size} bytes; limit={policy.max_archive_bytes}")
            return report
        if policy.max_age_hours is not None:
            age_hours = max(0.0, (time.time() - path.stat().st_mtime) / 3600.0)
            if age_hours > policy.max_age_hours:
                report.add("STALE_BACKUP", f"Archive age {age_hours:.1f}h exceeds {policy.max_age_hours}h")
        report.archive_sha256 = _hash_archive(path, policy.max_archive_bytes)
        handle, kind = _open_archive(path)
        report.format = kind
        with handle:
            items = _members(handle, kind, policy.max_members)
            safe = _validate_metadata(items, kind, policy, report)
            # Never process payload from a structurally unsafe archive.
            if report.findings:
                return report
            digests: dict[str, str] = {}
            for item in safe:
                if item.directory:
                    report.directories_checked += 1
                    continue
                try:
                    with _read_member(handle, kind, item) as stream:
                        digest, count = _copy_checked(stream, item.size, policy.max_file_bytes, policy.max_total_bytes - report.bytes_checked)
                    digests[item.name] = digest
                    report.bytes_checked += count
                    report.files_checked += 1
                except Exception as exc:  # fail closed on unexpected decoder/parser errors
                    report.add("PAYLOAD_INVALID", f"Unreadable payload: {exc}", item.name)
                    break
        _verify_unchanged(path, policy, report)
        if report.findings or not drill:
            return report
        # No archive supplied path is ever extracted by a library extractor.
        # An ephemeral owner-private directory isolates the actual restore drill.
        with tempfile.TemporaryDirectory(prefix="restoregate-") as root:
            rootpath = Path(root)
            with _open_archive(path)[0] as fresh:
                for item in safe:
                    destination = rootpath.joinpath(*item.name.split("/"))
                    if item.directory:
                        destination.mkdir(parents=True, exist_ok=True)
                        continue
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        with _read_member(fresh, kind, item) as source, destination.open("xb") as sink:
                            digest, count = _copy_checked(source, item.size, policy.max_file_bytes, policy.max_total_bytes - report.restored_bytes, sink)
                        if digest != digests[item.name]:
                            raise ArchiveReadError("Content changed between scan and drill")
                        with destination.open("rb") as restored:
                            readback, size_readback = _copy_checked(restored, count, policy.max_file_bytes, policy.max_total_bytes)
                        if readback != digest or size_readback != count:
                            raise ArchiveReadError("Restored bytes differ from source")
                        report.restored_files += 1
                        report.restored_bytes += count
                    except Exception as exc:  # fail closed on unexpected decoder/parser errors
                        report.add("DRILL_FAILED", f"Restore/readback failed: {exc}", item.name)
                        break
        _verify_unchanged(path, policy, report)
    except Exception as exc:  # malformed untrusted input must return a finding, not crash
        report.add("ARCHIVE_INVALID", f"Archive processing error: {exc}")
    return report
