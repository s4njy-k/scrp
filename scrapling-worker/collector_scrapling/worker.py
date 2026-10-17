"""Optional Scrapling alternate-acquisition worker (blueprint §4, §14).

Leases only jobs the router placed on stage 'scrapling' (policy
browser.alternate_engine: scrapling), under the same global browser permits,
shared attempt budget, fencing tokens and artifact contract as the primary
Crawlee/Playwright worker.

Scrapling settings are set explicitly instead of relying on library defaults:
no artificial Google referer, no resource suppression, no ad blocking, a
single internal attempt (the coordinator owns retries), a fixed locale and
the egress gateway as proxy. Its browser runs inside this container: a weaker
process/network boundary than the hardened driver/engine split (docs/security.md).
"""
from __future__ import annotations

import json
import logging
import os
import signal
import socket
import threading
import time
from typing import Any

import yaml

from . import db
from .contract import AttemptDir, Observation, classify, decide_terminal, evaluate_required, now_iso

log = logging.getLogger("scrapling-worker")
CHALLENGE_TITLES = ("just a moment", "attention required", "checking your browser", "ddos-guard", "verifying you are human")


def load_policy() -> dict[str, Any]:
    with open(os.environ.get("COLLECTOR_POLICY_PATH", "/app/config/policy.yaml"), encoding="utf-8") as fh:
        p = yaml.safe_load(fh)
    if p.get("schema_version") != 1 or p.get("project") != "cyber-web-collector":
        raise SystemExit("unsupported policy file")
    return p


def capture(url: str, policy: dict[str, Any], writer: AttemptDir, deadline: float, proxy: str | None) -> tuple[Observation, str | None, list[str], str | None]:
    """Run one Scrapling DynamicFetcher visit and preserve artifacts. Returns (observation, final_url, limitations, engine_version)."""
    from scrapling.fetchers import DynamicFetcher  # imported lazily: heavy

    cap = policy["capture"]
    br = policy["browser"]
    events: list[str] = []
    limitations = ["Scrapling DynamicFetcher adapter (browser in the worker container: weaker isolation than the hardened profile)"]
    state: dict[str, Any] = {"status": None, "net_error": None, "title": "", "text": "", "shots": 0, "final_url": None, "password": False, "version": None}
    max_events = policy["bounds"]["max_network_events_per_attempt"]

    def emit(e: dict[str, Any]) -> None:
        if len(events) < max_events:
            events.append(json.dumps({"at": now_iso(), **e}))

    def page_setup(page) -> None:  # registered BEFORE navigation (§9 step 1)
        page.on("request", lambda r: emit({"type": "request", "url": r.url, "method": r.method, "resource_type": r.resource_type}))
        page.on("response", lambda r: emit({"type": "response", "url": r.url, "status": r.status}))
        page.on("requestfailed", lambda r: emit({"type": "request_failed", "url": r.url, "failure": r.failure}))
        page.on("frameattached", lambda f: emit({"type": "frame_attached", "url": f.url}))
        page.on("websocket", lambda ws: emit({"type": "websocket_open", "url": ws.url}))
        page.on("dialog", lambda d: (emit({"type": "dialog", "message": d.message[:500], "action": "dismissed"}), d.dismiss()))
        page.on("download", lambda d: (emit({"type": "download_refused", "url": d.url}), d.cancel()))

    def shot(page, rel: str, kind: str) -> None:
        start = now_iso()
        try:
            data = page.screenshot(type="png", full_page=False, timeout=10000)
            if writer.write(rel, data, {"type": kind, "observedStart": start, "observedEnd": now_iso(), "creationMethod": "scrapling/playwright page.screenshot(viewport)",
                                         "completeness": "complete", "limitations": [], "metadata": {"page_url": page.url}}):
                state["shots"] += 1
        except Exception as err:  # noqa: BLE001 - recorded, never silent
            writer.missing({"type": kind, "observedStart": start, "observedEnd": now_iso(), "creationMethod": "page.screenshot", "completeness": "failed",
                            "limitations": [], "error": str(err)[:300]})

    def page_action(page) -> None:
        shot(page, "screenshots/01-early-viewport.png", "screenshot_early")
        try:
            page.wait_for_load_state("load", timeout=max(1000, min(br["readiness_max_seconds"] * 1000, (deadline - time.time() - 20) * 1000)))
        except Exception:  # noqa: BLE001
            emit({"type": "readiness_timeout"})
        shot(page, "screenshots/02-settled-viewport.png", "screenshot_settled")
        start = now_iso()
        try:
            html = page.content()
            limit = int(policy["bounds"]["max_dom_snapshot_mib"] * 1024 * 1024)
            raw = html.encode("utf-8")
            writer.write("dom/rendered.html", raw[:limit], {"type": "rendered_dom", "observedStart": start, "observedEnd": now_iso(),
                                                            "creationMethod": "page.content()", "completeness": "truncated" if len(raw) > limit else "complete", "limitations": []})
            text = page.evaluate("() => document.body ? document.body.innerText : ''")
            writer.write("dom/rendered.txt", text.encode("utf-8"), {"type": "rendered_text", "observedStart": start, "observedEnd": now_iso(),
                                                                     "creationMethod": "document.body.innerText", "completeness": "complete", "limitations": []})
            state.update(title=page.title(), text=text[:20000], final_url=page.url,
                         password=bool(page.evaluate("() => !!document.querySelector('input[type=password]')")))
        except Exception as err:  # noqa: BLE001
            writer.missing({"type": "rendered_dom", "observedStart": start, "observedEnd": now_iso(), "creationMethod": "page.content()",
                            "completeness": "failed", "limitations": [], "error": str(err)[:300]})
        state["version"] = f"chromium {page.context.browser.version}" if page.context.browser else None

    har_path = writer.tmp + "/network/network.har"
    os.makedirs(os.path.dirname(har_path), exist_ok=True)
    timeout_ms = int(max(5, deadline - time.time() - policy["limits"]["finalisation_reserve_seconds"]) * 1000)
    try:
        resp = DynamicFetcher.fetch(
            url,
            headless=True,
            disable_resources=cap["suppress_render_resources"],   # False: keep CSS/images/fonts (evidence mode)
            block_ads=cap["block_ads"],                           # False
            google_search=False,                                  # no artificial Google referer
            network_idle=False,                                   # never networkidle alone
            load_dom=True,
            timeout=timeout_ms,
            locale=br["locale"],
            proxy=proxy,
            retries=1,                                            # coordinator owns retries (§8)
            page_setup=page_setup,
            page_action=page_action,
            additional_args={"record_har_path": har_path, "record_har_content": "omit", "timezone_id": br["timezone"],
                             "viewport": cap["viewport"], "device_scale_factor": cap["device_scale_factor"],
                             "service_workers": cap["original_service_workers"]},
        )
        state["status"] = resp.status
        if state["final_url"] is None:
            state["final_url"] = resp.url
    except Exception as err:  # noqa: BLE001
        state["net_error"] = str(err)[:1000]
        limitations.append(f"fetch error: {state['net_error'][:200]}")

    writer.write("network/events.jsonl", ("\n".join(events) + "\n").encode("utf-8"), {
        "type": "network_events", "observedStart": None, "observedEnd": now_iso(), "creationMethod": "page listeners registered via Scrapling page_setup",
        "completeness": "truncated" if len(events) >= max_events else "complete", "limitations": ["only what this session observed"]})
    if os.path.exists(har_path):
        writer.entries.append({"type": "har", "path": "network/network.har", "observedStart": None, "observedEnd": now_iso(), "restricted": True,
                               "creationMethod": "Playwright record_har (content=omit) via Scrapling additional_args", "completeness": "complete",
                               "limitations": ["bodies omitted", "RESTRICTED: contains cookies/headers"]})
    else:
        writer.missing({"type": "har", "creationMethod": "record_har via additional_args", "completeness": "failed", "limitations": [],
                        "error": "HAR not produced by this Scrapling/Playwright combination; verify on the pinned versions"})

    title = (state["title"] or "").strip().lower()
    obs = Observation(
        status=state["status"], net_error=state["net_error"], content_appeared=bool(state["text"].strip()),
        challenge=any(title.startswith(t) for t in CHALLENGE_TITLES), auth_wall=state["password"],
        valid_screenshots=state["shots"], visible_text_length=len(state["text"]),
    )
    return obs, state["final_url"], limitations, state["version"]


def run_one(conn, policy: dict[str, Any], worker_id: str) -> bool:
    vantage = os.environ.get("EGRESS_VANTAGE_LABEL", "local-egress-gateway")
    lease = db.lease(conn, policy, worker_id, vantage)
    if not lease:
        return False
    stop = threading.Event()
    lost = threading.Event()

    def heartbeat() -> None:
        hb = db.connect()
        try:
            while not stop.wait(policy["queue"]["heartbeat_seconds"]):
                try:
                    if not db.renew(hb, lease, policy["queue"]["lease_seconds"]):
                        lost.set()
                        return
                except Exception:  # noqa: BLE001 - retry next beat
                    log.warning("heartbeat failed")
        finally:
            hb.close()

    t = threading.Thread(target=heartbeat, daemon=True)
    t.start()
    started = time.time()
    started_iso = now_iso()
    deadline = started + lease["seconds"]
    writer = AttemptDir(os.environ["ARTIFACT_ROOT"], lease["attempt_id"], int(policy["capture"]["attempt_artifacts_mib_max"] * 1024 * 1024))
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(f"UPDATE jobs SET state='CAPTURING' WHERE id=%s AND lease_token=%s AND state IN {db.ACTIVE}", (lease["job"]["id"], lease["token"]))
    required = lease["job"]["required_artifacts"]
    try:
        obs, final_url, limitations, version = capture(lease["job"]["url"], policy, writer, deadline, os.environ.get("EGRESS_PROXY_URL"))
        decided: dict[str, Any] = {}

        def base(artifacts):
            satisfied, missing = evaluate_required(required, artifacts)
            classification, outcome = classify(obs, satisfied)
            decided.update(decision=decide_terminal(classification, outcome, obs.valid_screenshots > 0))
            return {"attemptId": lease["attempt_id"], "jobId": lease["job"]["id"], "attemptNo": lease["attempt_no"], "kind": "browser",
                    "engine": "scrapling-dynamic", "adapter": "scrapling", "vantage": os.environ.get("EGRESS_VANTAGE_LABEL", "local-egress-gateway"),
                    "requestedUrl": lease["job"]["url"], "finalUrl": final_url, "startedAt": started_iso, "endedAt": now_iso(),
                    "outcome": outcome, "classification": classification, "requiredArtifacts": required,
                    "requiredSatisfied": satisfied and outcome == "CONTENT_CAPTURED", "missingRequired": missing,
                    "limitations": limitations + (["lease lost during capture"] if lost.is_set() else []), "engineVersion": version}

        rel_dir, manifest, sha, total = writer.finalise(base)
        retention = policy["retention"]["classes"].get(lease["job"]["retention_class"])
        db.commit(conn, lease, manifest, sha, rel_dir, total, time.time() - started, decided["decision"], None, retention)
    except Exception as err:  # noqa: BLE001 - infrastructure failure recorded as interruption
        log.exception("scrapling attempt failed")
        decision = {"kind": "finish", "state": "FAILED_FINAL", "outcome": "INFRASTRUCTURE_DEFERRED", "reason": f"infrastructure_error: {str(err)[:200]}"}
        try:
            db.commit(conn, lease, None, None, None, 0, time.time() - started, decision, str(err)[:1000], None)
        except Exception:  # noqa: BLE001 - lease expiry + reconciler will record it
            conn.rollback()
    finally:
        stop.set()
    return True


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(), format='{"level":"%(levelname)s","msg":"%(message)s"}')
    policy = load_policy()
    if policy["browser"]["alternate_engine"] != "scrapling":
        log.warning("policy browser.alternate_engine is not 'scrapling': this worker will stay idle")
    worker_id = f"scrapling-worker:{socket.gethostname()}:{os.getpid()}"
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    conn = db.connect()
    while not stopping.is_set():
        try:
            if not run_one(conn, policy, worker_id):
                stopping.wait(3)
        except Exception:  # noqa: BLE001 - database outage: pause, then retry
            log.exception("worker loop error")
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            stopping.wait(10)
            conn = db.connect()


if __name__ == "__main__":
    main()
