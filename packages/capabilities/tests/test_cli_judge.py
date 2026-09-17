"""`--judge` is opt-in: the default path is upstream's, byte for byte and import for import.

Three properties, one per section below.

1. **Nothing is imported unless asked.**  `capcov.cli` -- and a whole default
   `reconcile`/`gate` run through it -- must leave `sys.modules` free of every
   `capcov.claims` module.  The claims judge is behind a lazy import inside the
   branch `--judge claims` selects, the same way `capcov experiment` is behind a
   lazy import inside `main`.

2. **Asking incoherently is a usage error, not a verdict.**  `--judge claims`
   with no `--receipt`, an unknown engine in `capcov.toml`, a `--receipt` that
   is not a receipt directory, and `--receipt` without `--judge claims` all exit
   2 with a named message.  Exit 2 is argparse's code for "your command line
   does not name a run"; it is never a claim about the system under test.

3. **The tool is named when it is absent.**  With the Souffle interpreter off
   PATH, `--judge claims` fails with a message naming `souffle` and how to get
   it, and writes nothing -- the shape `capcov discover --resolver scip` uses
   for a missing indexer.

The default-path byte-identity of the *artifacts* is pinned separately, against
upstream's own output, in tests/claim_semantics/test_upstream_golden.py.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SRC = PACKAGE_ROOT / "src"
GOLDEN = PACKAGE_ROOT / "tests" / "claim_semantics" / "fixtures" / "upstream_golden"
PYTHON_APP = GOLDEN / "python_app"
RECEIPT = (PACKAGE_ROOT / "tests" / "claim_semantics" / "fixtures"
           / "replay_receipt_target_go_qualified")
MS = re.compile(rb'("[A-Za-z0-9_]*_ms":\s*)\d+')


def _env(**extra: str) -> dict[str, str]:
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    env.update(extra)
    return env


def _capcov(*argv: str, cwd: Path | None = None, env: dict[str, str] | None = None):
    return subprocess.run([sys.executable, "-m", "capcov", *argv], text=True,
                          capture_output=True, cwd=str(cwd) if cwd else None,
                          env=env or _env())


class ClaimsIsNotImportedUnlessAskedTests(unittest.TestCase):
    """The production CLI must not pay for -- or even load -- the experiment."""

    def test_importing_capcov_cli_imports_nothing_under_capcov_claims(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-c",
             "import sys, capcov.cli; "
             "assert not any(m.startswith('capcov.claims') for m in sys.modules), "
             "sorted(m for m in sys.modules if m.startswith('capcov.claims')); "
             "print('clean')"],
            text=True, capture_output=True, env=_env())
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "clean")

    def test_a_default_reconcile_and_gate_import_nothing_under_capcov_claims(self) -> None:
        """Not just the import: the whole default run leaves capcov.claims unloaded."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "coverage.json"
            script = (
                "import sys\n"
                "from capcov.cli import main\n"
                f"main(['reconcile', {str(PYTHON_APP / 'capabilities.json')!r}, "
                f"{str(PYTHON_APP / 'observed.json')!r}, '--out', {str(out)!r}, '--quiet'])\n"
                f"main(['gate', {str(out)!r}, '--quiet'])\n"
                "loaded = sorted(m for m in sys.modules if m.startswith('capcov.claims'))\n"
                "print('LOADED', loaded)\n"
            )
            proc = subprocess.run([sys.executable, "-c", script], text=True,
                                  capture_output=True, env=_env())
            self.assertIn("LOADED []", proc.stdout, proc.stdout + proc.stderr)

    def test_the_claims_branch_does_import_it(self) -> None:
        """The negative control: the property above is about the default, not about a dead branch."""
        probe = Path(tempfile.mkdtemp(prefix="capcov-judge-probe-"))
        self.addCleanup(shutil.rmtree, probe, ignore_errors=True)
        script = (
            "import sys\n"
            "from capcov.cli import main\n"
            "try:\n"
            f"    main(['gate', {str(PYTHON_APP / 'coverage.json')!r}, '--judge', 'claims', "
            f"'--receipt', {str(RECEIPT)!r}, '--judge-out', {str(probe / 'out')!r}])\n"
            # an absent souffle exits here; the import under test already happened
            "except SystemExit:\n"
            "    pass\n"
            "print('LOADED', bool([m for m in sys.modules if m.startswith('capcov.claims')]))\n"
        )
        proc = subprocess.run([sys.executable, "-c", script], text=True,
                              capture_output=True, env=_env())
        self.assertIn("LOADED True", proc.stdout, proc.stdout + proc.stderr)


class ExperimentNamespaceIsLazyTests(unittest.TestCase):
    """`capcov experiment claims ...` stays reachable -- and stays invisible to production."""

    def test_the_experiment_namespace_still_runs(self) -> None:
        proc = _capcov("experiment", "claims", "--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for subcommand in ("shen", "assumptions", "modelcheck"):
            self.assertIn(subcommand, proc.stdout)

    def test_the_production_help_does_not_mention_it(self) -> None:
        """`main` routes `experiment` before argparse, so it registers no subparser."""
        proc = _capcov("--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("experiment", proc.stdout)
        self.assertNotIn("claims", proc.stdout)


class JudgeUsageRefusalTests(unittest.TestCase):
    """Every incoherent ask is exit 2 with a named message, and judges nothing."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="capcov-judge-usage-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_claims_without_a_receipt_exits_two_on_gate(self) -> None:
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--judge", "claims")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("pass --receipt DIR", proc.stderr)
        self.assertIn("capcov gate --judge claims", proc.stderr)

    def test_claims_without_a_receipt_exits_two_on_reconcile(self) -> None:
        proc = _capcov("reconcile", str(PYTHON_APP / "capabilities.json"),
                       str(PYTHON_APP / "observed.json"),
                       "--out", str(self.tmp / "coverage.json"), "--judge", "claims")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("pass --receipt DIR", proc.stderr)
        # refused before any work: reconcile did not write its artifact either
        self.assertFalse((self.tmp / "coverage.json").exists())

    def test_an_unknown_engine_in_capcov_toml_exits_two(self) -> None:
        (self.tmp / "capcov.toml").write_text('[judge]\nengine = "hand-waving"\n')
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), cwd=self.tmp)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("unknown judge engine 'hand-waving'", proc.stderr)
        self.assertIn("four-cell, claims", proc.stderr)

    def test_an_unknown_engine_on_the_flag_exits_two(self) -> None:
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--judge", "hand-waving")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("invalid choice", proc.stderr)

    def test_the_capcov_toml_key_selects_the_claims_judge(self) -> None:
        """The key is read, not decorative: with no --receipt it produces the claims refusal."""
        (self.tmp / "capcov.toml").write_text('[judge]\nengine = "claims"\n')
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), cwd=self.tmp)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("--judge claims", proc.stderr)
        self.assertIn("pass --receipt DIR", proc.stderr)

    def test_a_directory_that_is_not_a_receipt_exits_two(self) -> None:
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"),
                       "--judge", "claims", "--receipt", str(self.tmp))
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("is not a replay receipt directory", proc.stderr)

    def test_a_receipt_without_the_claims_judge_is_refused_not_ignored(self) -> None:
        """A flag that silently does nothing is how a gate goes green for the wrong reason."""
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--receipt", str(RECEIPT))
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("--receipt is only meaningful with --judge claims", proc.stderr)

    def test_a_judge_out_without_the_claims_judge_is_refused(self) -> None:
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"),
                       "--judge-out", str(self.tmp / "j"))
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("--judge-out is only meaningful with --judge claims", proc.stderr)


class DefaultJudgeIsTodaysBehaviorTests(unittest.TestCase):
    """`--judge four-cell` is the default, and naming it changes nothing."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="capcov-judge-default-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _reconcile(self, name: str, *extra: str):
        out = self.tmp / name
        proc = _capcov("reconcile", str(PYTHON_APP / "capabilities.json"),
                       str(PYTHON_APP / "observed.json"), "--out", str(out), *extra)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # only the wall-clock timings differ between two runs of the same reconcile
        return proc.stdout, MS.sub(rb"\g<1>0", out.read_bytes())

    def test_naming_the_default_engine_is_byte_identical_to_not_naming_it(self) -> None:
        bare_stdout, bare = self._reconcile("bare.json")
        named_stdout, named = self._reconcile("named.json", "--judge", "four-cell")
        self.assertEqual(bare, named)
        self.assertEqual(bare_stdout, named_stdout)
        self.assertNotIn("judge", json.loads(bare))

    def test_a_capcov_toml_with_no_judge_block_is_the_four_cell_judge(self) -> None:
        (self.tmp / "capcov.toml").write_text('[capcov]\nadapter = "python-fastapi-sqlalchemy"\n')
        out = self.tmp / "from-config.json"
        proc = _capcov("reconcile", str(PYTHON_APP / "capabilities.json"),
                       str(PYTHON_APP / "observed.json"), "--out", str(out), cwd=self.tmp)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        _, bare = self._reconcile("bare2.json")
        self.assertEqual(MS.sub(rb"\g<1>0", out.read_bytes()), bare)

    def test_a_capcov_toml_that_does_not_parse_does_not_break_the_default_run(self) -> None:
        """reconcile/gate never read capcov.toml before --judge existed; a broken one
        must not turn a working default run into a failure."""
        (self.tmp / "capcov.toml").write_text("this is not = = toml\n")
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), cwd=self.tmp)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("capcov gate: FAIL -- 4 unexplained", proc.stdout)

    def test_an_explicit_flag_is_never_lost_to_an_unreadable_capcov_toml(self) -> None:
        (self.tmp / "capcov.toml").write_text("this is not = = toml\n")
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--judge", "claims",
                       cwd=self.tmp)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("pass --receipt DIR", proc.stderr)

    def test_the_default_gate_is_the_four_cell_gate(self) -> None:
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"))
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("capcov gate: FAIL -- 4 unexplained", proc.stdout)


@unittest.skipIf(shutil.which("souffle") is not None,
                 "this pins the message when souffle is ABSENT; it is on PATH here")
class AbsentToolIsNamedTests(unittest.TestCase):
    """The `--resolver scip` convention: name the tool, name the fix, judge nothing."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="capcov-judge-absent-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_gate_names_souffle_and_writes_no_judge_artifacts(self) -> None:
        out = self.tmp / "judge"
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--judge", "claims",
                       "--receipt", str(RECEIPT), "--judge-out", str(out))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("capcov gate --judge claims:", proc.stderr)
        self.assertIn("souffle", proc.stderr)
        self.assertIn("Install it with:", proc.stderr)
        self.assertFalse(out.exists(), "a refused judge must leave no artifacts behind")

    def test_reconcile_still_wrote_its_own_artifact_before_the_judge_refused(self) -> None:
        """reconcile is the producer of coverage.json under either judge."""
        coverage = self.tmp / "coverage.json"
        proc = _capcov("reconcile", str(PYTHON_APP / "capabilities.json"),
                       str(PYTHON_APP / "observed.json"), "--out", str(coverage),
                       "--judge", "claims", "--receipt", str(RECEIPT),
                       "--judge-out", str(self.tmp / "judge"))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("souffle", proc.stderr)
        self.assertEqual(json.loads(coverage.read_text())["kind"], "coverage")


if __name__ == "__main__":
    unittest.main()
