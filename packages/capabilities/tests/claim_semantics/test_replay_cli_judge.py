"""`capcov gate --judge claims` really judges: the live path, souffle present.

The host-side suite (tests/test_cli_judge.py) pins what happens when nobody asks
and when the toolchain is absent.  This one is the other half: with the Souffle
interpreter on PATH, the CLI's claims branch runs the same judge the cross-repo
``scripts/compiled_checker.py`` runs, over the committed receipt fixtures, and
its answers are the documented ones.

Two receipts, two answers, and the difference between them is the point:

* the **synthetic** receipt carries a Stage D typed-checker certificate (every
  fact in it is made up, which is exactly why it is the only fixture that can
  exercise the positive path while the checker does not exist) -> ``supported``,
  CLI exit 0;
* the **real** target-go receipt does not -> ``pending-premise``, judge exit 5,
  CLI exit 1.  The CLI collapses the judge's six exit codes to a gate's one
  question, so this test also pins that the collapse is lossless *on paper*:
  judge.json still carries ``exit_code: 5`` and names the pending premise.

souffle is a precondition rather than a skip in the devShell; outside it this
class skips, because an absent interpreter is pinned elsewhere.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
COVERAGE = FIXTURES / "upstream_golden" / "python_app" / "coverage.json"
SYNTHETIC = FIXTURES / "replay_receipt_min"
QUALIFIED = FIXTURES / "replay_receipt_target_go_qualified"


@unittest.skipIf(shutil.which("souffle") is None,
                 "the live claims judge needs the souffle interpreter: run inside `nix develop`")
class ClaimsJudgeCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="capcov-cli-judge-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _gate(self, receipt: Path, out: str):
        proc = subprocess.run(
            [sys.executable, "-m", "capcov", "gate", str(COVERAGE), "--judge", "claims",
             "--receipt", str(receipt), "--judge-out", str(self.tmp / out)],
            text=True, capture_output=True,
            env={**os.environ, "PYTHONPATH": str(PACKAGE_ROOT / "src")})
        document = json.loads((self.tmp / out / "judge.json").read_text())
        return proc, document

    def test_the_synthetic_receipt_is_supported_and_the_gate_passes(self) -> None:
        proc, document = self._gate(SYNTHETIC, "synthetic")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(document["verdict"], "supported")
        self.assertEqual(document["exit_code"], 0)
        self.assertTrue(document["kernels"]["matched"])
        # two kernels on this path: python and the interpreter, no compiled binary
        self.assertIsNone(document["compiled"])
        self.assertIn("supported", proc.stdout)

    def test_the_real_receipt_is_pending_the_checker_and_the_gate_fails(self) -> None:
        proc, document = self._gate(QUALIFIED, "qualified")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(document["verdict"], "pending-premise")
        # the gate answers 0/1; the distinction the producer repo gates on survives here
        self.assertEqual(document["exit_code"], 5)
        self.assertTrue(document["pending_ops"])
        self.assertIn("pending", proc.stderr + proc.stdout)

    def test_the_judge_writes_its_certificates_beside_judge_json(self) -> None:
        _, _ = self._gate(SYNTHETIC, "artifacts")
        written = {path.name for path in (self.tmp / "artifacts").rglob("*") if path.is_file()}
        self.assertIn("judge.json", written)
        self.assertGreater(len(written), 1, "the judge writes certificates, not just a verdict")

    def test_a_malformed_receipt_is_a_named_contract_finding_not_a_traceback(self) -> None:
        broken = self.tmp / "broken-receipt"
        shutil.copytree(SYNTHETIC, broken)
        (broken / "receipt.json").write_text("{not json")
        proc = subprocess.run(
            [sys.executable, "-m", "capcov", "gate", str(COVERAGE), "--judge", "claims",
             "--receipt", str(broken), "--judge-out", str(self.tmp / "broken-out")],
            text=True, capture_output=True,
            env={**os.environ, "PYTHONPATH": str(PACKAGE_ROOT / "src")})
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("contract finding", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_no_artifact_carries_a_local_path(self) -> None:
        """The public-repo rule: digests, counts and verdicts, never a producing path."""
        self._gate(SYNTHETIC, "paths")
        for path in (self.tmp / "paths").rglob("*"):
            if path.is_file():
                with self.subTest(path.name):
                    self.assertNotIn(str(PACKAGE_ROOT), path.read_text())


if __name__ == "__main__":
    unittest.main()
