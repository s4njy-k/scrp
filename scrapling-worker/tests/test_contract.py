"""Run: python3 -I scrapling-worker/tests/test_contract.py -v
These pin behaviour shared with src/acquisition/contract.ts and src/router/router.ts."""
import json
import os
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from collector_scrapling.contract import AttemptDir, Observation, classify, decide_terminal, evaluate_required  # noqa: E402


def entry(t, completeness="complete", path="x"):
    return {"type": t, "path": path, "sha256": "h" if path else None, "completeness": completeness}


class ContractTests(unittest.TestCase):
    def test_required_evaluation_matches_typescript_rules(self):
        req = ["screenshot_viewport", "rendered_dom", "har", "manifest"]
        self.assertEqual(evaluate_required(req, [entry("screenshot_settled"), entry("rendered_dom"), entry("har", "truncated")]), (True, []))
        self.assertEqual(evaluate_required(req, [entry("screenshot_settled", "failed", None), entry("rendered_dom"), entry("har")])[1], ["screenshot_viewport"])
        self.assertEqual(evaluate_required(req, [entry("screenshot_settled"), entry("rendered_dom", "truncated"), entry("har")])[1], ["rendered_dom"])

    def test_alternate_stage_decisions_are_terminal(self):
        ok = Observation(200, None, True, False, False, 2, 900)
        self.assertEqual(decide_terminal(*classify(ok, True), True)["state"], "COMPLETE")
        ch = Observation(403, None, True, True, False, 1, 50)
        self.assertEqual(classify(ch, False), ("challenge", "CHALLENGE_PAGE_CAPTURED"))
        self.assertEqual(decide_terminal(*classify(ch, False), True)["state"], "MANUAL_REVIEW")
        blocked = Observation(403, None, True, False, False, 1, 50)
        self.assertEqual(decide_terminal(*classify(blocked, True), True)["state"], "FAILED_FINAL")
        partial = Observation(200, None, True, False, False, 1, 900)
        self.assertEqual(decide_terminal(*classify(partial, False), True)["state"], "PARTIAL")

    def test_attempt_dir_hashes_and_renames(self):
        with tempfile.TemporaryDirectory() as root:
            aid = str(uuid.uuid4())
            w = AttemptDir(root, aid, 1024)
            w.write("dom/rendered.txt", b"hello", {"type": "rendered_text", "creationMethod": "t", "completeness": "complete", "limitations": []})
            self.assertFalse(w.write("big.bin", b"x" * 2048, {"type": "response_body", "creationMethod": "t", "completeness": "complete", "limitations": []}))
            w.missing({"type": "har", "creationMethod": "t", "completeness": "failed", "limitations": [], "error": "x"})
            rel, manifest, sha, total = w.finalise(lambda arts: {"startedAt": "2026-10-17T00:00:00Z", "attemptId": aid})
            self.assertTrue(rel.startswith("captures/2026/10/17/"))
            with open(os.path.join(root, rel, "manifest.json"), encoding="utf-8") as fh:
                m = json.load(fh)
            types = {a["type"]: a for a in m["artifacts"]}
            self.assertEqual(types["rendered_text"]["sha256"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
            self.assertEqual(types["response_body"]["completeness"], "omitted")
            self.assertIsNone(types["har"]["path"])
            self.assertFalse(os.path.exists(os.path.join(root, "tmp", aid)))

    def test_rejects_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as root:
            w = AttemptDir(root, str(uuid.uuid4()), 1024)
            with self.assertRaises(ValueError):
                w.write("../escape", b"x", {"type": "x", "creationMethod": "t", "completeness": "complete", "limitations": []})
        with self.assertRaises(ValueError):
            AttemptDir("/tmp", "not-a-uuid", 1)


if __name__ == "__main__":
    unittest.main()
