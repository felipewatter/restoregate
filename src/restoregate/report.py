"""Deterministic JSON and SARIF evidence output."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    code: str
    message: str
    path: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    archive: str
    mode: str
    format: str = "unknown"
    files_checked: int = 0
    directories_checked: int = 0
    bytes_checked: int = 0
    archive_sha256: str | None = None
    restored_files: int = 0
    restored_bytes: int = 0
    findings: list[Finding] = field(default_factory=list)
    policy: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.findings

    def add(self, code: str, message: str, path: str | None = None) -> None:
        self.findings.append(Finding(code, message, path))

    def as_dict(self) -> dict:
        data = asdict(self)
        data["schema_version"] = "1.0"
        data["ok"] = self.ok
        return data

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), sort_keys=True, indent=2, ensure_ascii=False) + "\n"

    def to_sarif(self) -> str:
        rules = sorted({f.code for f in self.findings})
        results: list[dict[str, Any]] = []
        for finding in self.findings:
            loc = finding.path or self.archive
            results.append({
                "ruleId": finding.code,
                "level": "error",
                "message": {"text": finding.message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc}}}],
            })
        data = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "RestoreGate", "version": "0.1.0", "rules": [
                {"id": k, "shortDescription": {"text": k.replace("_", " ").title()}} for k in rules
            ]}}, "results": results}],
        }
        return json.dumps(data, sort_keys=True, indent=2) + "\n"


def write_report(path: str, content: str) -> None:
    # Explicit output is intentional; avoid partial results on failure.
    import os
    import tempfile
    target = Path(path)
    parent = target.absolute().parent
    if not parent.is_dir():
        raise OSError(f"Report directory does not exist: {parent}")
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=parent, prefix=".restoregate-", delete=False) as stream:
            tmp = stream.name
            stream.write(content)
        os.replace(tmp, target)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)
