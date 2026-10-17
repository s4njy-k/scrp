"""Shared job/result contract for the optional Scrapling adapter.

Mirrors src/acquisition/contract.ts and the alternate-stage branch of
src/router/router.ts (blueprint §7, §8, §12). The TypeScript implementation is
authoritative; tests in tests/test_contract.py pin the behaviour that must stay
identical (required-artifact evaluation and terminal decisions).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

ATTEMPT_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SAFE_REL_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*(/[a-z0-9][a-z0-9_.-]*)*$")

SATISFIABLE_WHEN_PARTIAL = {"network_events", "har", "screenshot_full_or_tiles"}
SATISFIED_BY = {
    "screenshot_viewport": {"screenshot_viewport", "screenshot_early", "screenshot_settled"},
    "screenshot_full_or_tiles": {"screenshot_full_or_tiles"},
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def evaluate_required(required: list[str], entries: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """Same rules as evaluateRequired() in contract.ts."""
    missing: list[str] = []
    for req in required:
        if req == "manifest":
            continue
        acceptable = SATISFIED_BY.get(req, {req})
        ok = False
        for e in entries:
            if e["type"] not in acceptable or not e.get("path") or not e.get("sha256"):
                continue
            if e["completeness"] == "complete":
                ok = True
            elif e["completeness"] in ("truncated", "partial") and req in SATISFIABLE_WHEN_PARTIAL:
                ok = True
            if ok:
                break
        if not ok:
            missing.append(req)
    return (not missing, missing)


@dataclass
class Observation:
    status: int | None
    net_error: str | None
    content_appeared: bool
    challenge: bool
    auth_wall: bool
    valid_screenshots: int
    visible_text_length: int
    signals: list[str] = field(default_factory=list)


def classify(o: Observation, required_satisfied: bool) -> tuple[str, str]:
    """(classification, outcome) — the subset of classifyBrowser() relevant here."""
    if o.net_error and not o.content_appeared:
        m = o.net_error.upper()
        if "NAME_NOT_RESOLVED" in m or "DNS" in m:
            return "dns_failure", "DNS_FAILURE"
        if "CERT" in m or "SSL" in m or "TLS" in m:
            return "tls_failure", "TLS_FAILURE"
        if "DENIED" in m:
            return "egress_denied", "ACCESS_BLOCKED"
        return "connection_reset", "ORIGIN_UNAVAILABLE"
    if o.challenge:
        return "challenge", "CHALLENGE_PAGE_CAPTURED"
    status = o.status or 200
    if status == 429:
        return "rate_limited", "ACCESS_BLOCKED"
    if status == 401 or (o.auth_wall and o.visible_text_length < 1500):
        return "auth_required", "AUTH_REQUIRED"
    if status in (403, 451):
        return "access_denied", "ACCESS_BLOCKED"
    if status in (404, 410):
        return "not_found", "NOT_FOUND"
    if status >= 500 and o.visible_text_length < 200:
        return "server_error", "ORIGIN_UNAVAILABLE"
    if not o.content_appeared:
        return "content_incomplete", "CONTENT_INCOMPLETE"
    if not required_satisfied:
        return "content_incomplete", "CONTENT_INCOMPLETE"
    return "content_captured", "CONTENT_CAPTURED"


def decide_terminal(classification: str, outcome: str, useful: bool) -> dict[str, Any]:
    """The alternate stage is the last escalation: every result is terminal (§8)."""
    def finish(state: str, reason: str) -> dict[str, Any]:
        return {"kind": "finish", "state": state, "outcome": outcome, "reason": f"{classification}: {reason}"}

    if classification == "content_captured":
        return finish("COMPLETE", "required artifact contract satisfied (scrapling adapter)")
    if classification in ("challenge", "auth_required", "egress_denied"):
        return finish("MANUAL_REVIEW", "alternate adapter could not resolve; operator attention required")
    if useful and outcome in ("CONTENT_CAPTURED", "CONTENT_INCOMPLETE"):
        return finish("PARTIAL", "useful evidence preserved by alternate adapter")
    return finish("FAILED_FINAL", "alternate adapter attempt exhausted the budget")


class AttemptDir:
    """Temp directory -> hashed manifest -> atomic rename (same layout as artifactStore.ts)."""

    def __init__(self, root: str, attempt_id: str, budget_bytes: int):
        if not ATTEMPT_ID_RE.match(attempt_id):
            raise ValueError("attempt id must be a UUID")
        self.root = root
        self.attempt_id = attempt_id
        self.tmp = os.path.join(root, "tmp", attempt_id)
        self.budget = budget_bytes
        self.used = 0
        self.entries: list[dict[str, Any]] = []
        os.makedirs(self.tmp, mode=0o750, exist_ok=True)

    def write(self, rel: str, data: bytes, entry: dict[str, Any]) -> bool:
        if not SAFE_REL_RE.match(rel) or ".." in rel.split("/"):
            raise ValueError(f"unsafe artifact path {rel!r}")
        if self.used + len(data) > self.budget:
            self.entries.append({**entry, "path": None, "completeness": "omitted", "error": "attempt_artifact_budget_exceeded"})
            return False
        self.used += len(data)
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if entry.get("restricted") else 0o640)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        self.entries.append({**entry, "path": rel})
        return True

    def missing(self, entry: dict[str, Any]) -> None:
        self.entries.append({**entry, "path": None})

    def finalise(self, build_base) -> tuple[str, dict[str, Any], str, int]:
        artifacts: list[dict[str, Any]] = []
        total = 0
        for e in self.entries:
            base = {"limitations": [], "observedStart": None, "observedEnd": None, **e}
            if not e.get("path"):
                artifacts.append({**base, "sizeBytes": None, "sha256": None})
                continue
            p = os.path.join(self.tmp, e["path"])
            try:
                with open(p, "rb") as fh:
                    data = fh.read()
                total += len(data)
                artifacts.append({**base, "sizeBytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            except OSError as err:
                artifacts.append({**base, "path": None, "sizeBytes": None, "sha256": None, "completeness": "failed", "error": f"file missing at finalisation: {err}"})
        manifest = {"manifestVersion": 1, **build_base(artifacts), "artifacts": artifacts}
        text = json.dumps(manifest, indent=2) + "\n"
        mpath = os.path.join(self.tmp, "manifest.json")
        with open(mpath, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        started = datetime.fromisoformat(manifest["startedAt"].replace("Z", "+00:00"))
        rel_dir = f"captures/{started:%Y/%m/%d}/{self.attempt_id}"
        final = os.path.join(self.root, rel_dir)
        os.makedirs(os.path.dirname(final), mode=0o750, exist_ok=True)
        os.rename(self.tmp, final)
        dfd = os.open(os.path.dirname(final), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        return rel_dir, manifest, hashlib.sha256(text.encode()).hexdigest(), total + len(text.encode())
