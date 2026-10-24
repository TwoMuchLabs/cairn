"""Runs lesson rules through Opengrep (preferred) or Semgrep CE."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ENGINE_CANDIDATES = ("opengrep", "semgrep")


class EngineNotFound(Exception):
    pass


@dataclass(frozen=True)
class Engine:
    name: str
    path: str

    def version(self) -> str:
        try:
            cmd = [self.path, "--version"]
            if self.name.startswith("semgrep"):
                cmd.append("--disable-version-check")
            out = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                stdin=subprocess.DEVNULL,
                check=False,
            )
            return (out.stdout or out.stderr).strip().splitlines()[0]
        except (OSError, subprocess.SubprocessError, IndexError):
            return "unknown"


@dataclass
class RawFinding:
    rule_id: str
    path: Path
    start_line: int
    end_line: int
    message: str
    metadata: dict[str, Any]


@dataclass
class EngineResult:
    findings: list[RawFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def find_engine() -> Engine:
    """Locate a rule engine. CAIRN_ENGINE may name a binary or a path."""
    override = os.environ.get("CAIRN_ENGINE")
    if override:
        path = shutil.which(override) or (override if Path(override).exists() else None)
        if not path:
            raise EngineNotFound(f"CAIRN_ENGINE={override!r} was not found on PATH")
        return Engine(name=Path(override).name, path=path)
    for name in ENGINE_CANDIDATES:
        path = shutil.which(name)
        if path:
            return Engine(name=name, path=path)
    raise EngineNotFound(
        "No rule engine found. Install Opengrep (recommended: "
        "https://github.com/opengrep/opengrep) or Semgrep CE (pip install semgrep)."
    )


def _command(
    engine: Engine, config: Path, targets: Sequence[Path], extra: Sequence[str]
) -> list[str]:
    cmd = [engine.path, "scan", "--config", str(config), "--json", "--quiet"]
    if engine.name.startswith("semgrep"):
        cmd += ["--metrics=off", "--disable-version-check"]
    cmd += list(extra)
    cmd += [str(t) for t in targets]
    return cmd


def run(
    engine: Engine,
    rules: list[dict[str, Any]],
    targets: Sequence[Path],
    *,
    extra_args: Sequence[str] = (),
    cwd: Path | None = None,
    timeout: int = 900,
) -> EngineResult:
    """Run a set of rules over targets and return normalised findings."""
    if not rules or not targets:
        return EngineResult()
    with tempfile.TemporaryDirectory(prefix="cairn-") as tmp:
        config = Path(tmp) / "rules.yaml"
        config.write_text(yaml.safe_dump({"rules": rules}, sort_keys=False), "utf-8")
        cmd = _command(engine, config, targets, extra_args)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return EngineResult(errors=[f"{engine.name} timed out after {timeout}s"])
        except OSError as exc:
            return EngineResult(errors=[f"could not start {engine.name}: {exc}"])

    if not (proc.stdout or "").strip():
        tail = (proc.stderr or "").strip().splitlines()[-3:]
        return EngineResult(
            errors=[
                f"{engine.name} produced no output (exit {proc.returncode}): " + " | ".join(tail)
            ]
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-5:]
        return EngineResult(errors=[f"{engine.name} exited {proc.returncode}: " + " | ".join(tail)])

    result = EngineResult()
    base = Path(cwd) if cwd else Path.cwd()
    for r in payload.get("results", []):
        extra = r.get("extra", {})
        p = Path(r["path"])
        result.findings.append(
            RawFinding(
                rule_id=_strip_rule_prefix(r.get("check_id", "")),
                path=p if p.is_absolute() else (base / p),
                start_line=int(r["start"]["line"]),
                end_line=int(r["end"]["line"]),
                message=" ".join(str(extra.get("message", "")).split()),
                metadata=extra.get("metadata", {}) or {},
            )
        )
    for e in payload.get("errors", []):
        level = e.get("level", "error")
        if level == "error":
            result.errors.append(" ".join(str(e.get("message", e)).split()))
    return result


def _strip_rule_prefix(check_id: str) -> str:
    # Engines prefix rule ids with the config path, e.g. "tmp.cairn-x.rules.my-rule".
    return check_id.rsplit(".", 1)[-1] if check_id else check_id
