"""RestoreGate CLI: stable exit codes for automation."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import analyze_archive
from .policy import load_policy, PolicyError
from .report import write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="restoregate", description="Offline ZIP/TAR restore-readiness gate. Does not execute backup contents.")
    parser.add_argument("--version", action="version", version=f"RestoreGate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "drill"):
        child = sub.add_parser(name, help="Inspect every file without extraction" if name == "scan" else "Perform isolated, temporary restore and readback")
        child.add_argument("archive", help="ZIP, TAR, TAR.GZ, TAR.BZ2 or TAR.XZ archive path")
        child.add_argument("--policy", help="Validated JSON policy file")
        child.add_argument("--format", choices=("text", "json"), default="text", help="stdout report format")
        child.add_argument("--json-out", help="Write JSON evidence to a file atomically")
        child.add_argument("--sarif-out", help="Write SARIF 2.1.0 findings to a file atomically")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print(f"Policy error: {exc}", file=sys.stderr)
        return 2
    report = analyze_archive(args.archive, policy=policy, drill=args.command == "drill")
    try:
        if args.json_out:
            write_report(args.json_out, report.to_json())
        if args.sarif_out:
            write_report(args.sarif_out, report.to_sarif())
    except OSError as exc:
        print(f"Evidence write error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(report.to_json(), end="")
    else:
        print(f"RestoreGate {__version__} | {report.mode.upper()} | {'PASS' if report.ok else 'FAIL'}")
        print(f"Archive: {report.archive} ({report.format}), files: {report.files_checked}, bytes verified: {report.bytes_checked}")
        if report.mode == "drill":
            print(f"Restored/readback: {report.restored_files} files, {report.restored_bytes} bytes (temporary directory removed)")
        print(f"Archive SHA-256: {report.archive_sha256 or 'unavailable'}")
        for finding in report.findings:
            print(f"[{finding.code}] {finding.path + ': ' if finding.path else ''}{finding.message}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
