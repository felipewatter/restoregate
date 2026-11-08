"""Strictly validated, dependency-free restore policy."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import math
from pathlib import Path


@dataclass(frozen=True)
class Policy:
    max_archive_bytes: int = 1_073_741_824
    max_total_bytes: int = 1_073_741_824
    max_file_bytes: int = 268_435_456
    max_members: int = 10_000
    max_ratio: float = 200.0
    max_depth: int = 32
    max_age_hours: float | None = None
    min_files: int = 1
    required_paths: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        result = asdict(self)
        result["required_paths"] = list(self.required_paths)
        return result


class PolicyError(ValueError):
    """Policy is structurally invalid."""


def load_policy(path: str | Path | None) -> Policy:
    if path is None:
        return Policy()
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"Cannot read policy JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("Policy must be a JSON object")
    keys = set(Policy.__dataclass_fields__)
    unknown = set(data) - keys
    if unknown:
        raise PolicyError(f"Unknown policy keys: {', '.join(sorted(unknown))}")
    defaults = Policy().as_dict()
    defaults.update(data)
    integer_fields = ("max_archive_bytes", "max_total_bytes", "max_file_bytes", "max_members", "max_depth")
    for name in integer_fields:
        val = defaults[name]
        if type(val) is not int or val <= 0:
            raise PolicyError(f"{name} must be a positive integer")
    val = defaults["min_files"]
    if type(val) is not int or val < 0:
        raise PolicyError("min_files must be a non-negative integer")
    for name in ("max_ratio", "max_age_hours"):
        val = defaults[name]
        if name == "max_age_hours" and val is None:
            continue
        if type(val) not in (int, float) or not math.isfinite(val) or val <= 0:
            raise PolicyError(f"{name} must be a positive finite number")
    rp = defaults["required_paths"]
    if not isinstance(rp, list) or not all(isinstance(p, str) for p in rp):
        raise PolicyError("required_paths must be a list of strings")
    # local import avoids policy-path validation circular dependency
    from .paths import validate_member_path
    for p in rp:
        reason = validate_member_path(p)
        if reason:
            raise PolicyError(f"Invalid required_path {p!r}: {reason}")
    defaults["required_paths"] = tuple(rp)
    return Policy(**defaults)
