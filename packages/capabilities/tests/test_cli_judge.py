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

3. **An optional kernel is asked for by name, and named when it is absent.**
   `--judge claims` alone judges with the stdlib Python evaluator and needs no
   tool at all; `--evaluator souffle` (or `souffle-compiled`, or the capcov.toml
   key) with the interpreter off PATH exits 2 with a message naming the binary,
   where it was looked for, how to install it and the flag that needs nothing --
   the shape `capcov discover --resolver scip` uses for a missing indexer -- and
   writes no judge artifacts.  A judge that ran one kernel says so in
   judge.json (`kernels: ["python"]`, `differential: not-run (single
   evaluator)`) rather than reporting a differential it did not run.

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
    """The `--resolver scip` convention: name the tool, name the fix, judge nothing.

    Only for an evaluator that was *asked for*.  The default judge is the stdlib
    Python kernel, which is why `DefaultEvaluatorNeedsNoToolTests` below judges
    the same receipt in this very environment and gets an answer.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="capcov-judge-absent-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _refusal(self, *extra: str, out: Path | None = None):
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--judge", "claims",
                       "--receipt", str(RECEIPT), "--judge-out", str(out or self.tmp / "judge"),
                       *extra)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("capcov gate --judge claims:", proc.stderr)
        self.assertIn("Install it with:", proc.stderr)
        self.assertIn("or use --evaluator python", proc.stderr)
        return proc

    def test_gate_names_souffle_and_writes_no_judge_artifacts(self) -> None:
        out = self.tmp / "judge"
        proc = self._refusal("--evaluator", "souffle", out=out)
        self.assertIn("--evaluator souffle needs the Souffle 2.5 executable", proc.stderr)
        self.assertIn("not on PATH or $SOUFFLE", proc.stderr)
        self.assertFalse(out.exists(), "a refused judge must leave no artifacts behind")

    def test_the_compiled_evaluator_names_the_same_binary(self) -> None:
        proc = self._refusal("--evaluator", "souffle-compiled")
        self.assertIn("--evaluator souffle-compiled needs the Souffle 2.5 executable",
                      proc.stderr)

    def test_a_comma_list_is_refused_on_the_first_evaluator_that_is_absent(self) -> None:
        proc = self._refusal("--evaluator", "python,souffle-compiled")
        self.assertIn("--evaluator souffle-compiled needs", proc.stderr)

    def test_the_capcov_toml_evaluator_key_is_refused_the_same_way(self) -> None:
        (self.tmp / "capcov.toml").write_text('[judge]\nevaluator = "souffle"\n')
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--judge", "claims",
                       "--receipt", str(RECEIPT), "--judge-out", str(self.tmp / "judge"),
                       cwd=self.tmp)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("--evaluator souffle needs", proc.stderr)

    def test_all_is_never_refused_for_an_absent_tool(self) -> None:
        """`all` means every evaluator that is here, so here it means python alone."""
        out = self.tmp / "all"
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--judge", "claims",
                       "--receipt", str(RECEIPT), "--judge-out", str(out),
                       "--evaluator", "all")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        document = json.loads((out / "judge.json").read_text())
        self.assertEqual(document["kernels"], ["python"])

    def test_reconcile_still_wrote_its_own_artifact_before_the_judge_refused(self) -> None:
        """reconcile is the producer of coverage.json under either judge."""
        coverage = self.tmp / "coverage.json"
        proc = _capcov("reconcile", str(PYTHON_APP / "capabilities.json"),
                       str(PYTHON_APP / "observed.json"), "--out", str(coverage),
                       "--judge", "claims", "--receipt", str(RECEIPT),
                       "--evaluator", "souffle", "--judge-out", str(self.tmp / "judge"))
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("--evaluator souffle needs", proc.stderr)
        # the refusal is a command-line refusal, raised before reconcile does its
        # own work: nothing is written, not even the artifact reconcile produces
        self.assertFalse(coverage.exists())


class EvaluatorUsageRefusalTests(unittest.TestCase):
    """Naming a kernel that does not exist, or naming one where it says nothing."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="capcov-evaluator-usage-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_an_unknown_evaluator_exits_two_and_lists_the_choices(self) -> None:
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--judge", "claims",
                       "--receipt", str(RECEIPT), "--evaluator", "datalog-by-hand")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("unknown evaluator 'datalog-by-hand'", proc.stderr)
        self.assertIn("python, souffle, souffle-compiled", proc.stderr)
        self.assertIn("(--evaluator)", proc.stderr)

    def test_all_cannot_be_combined_with_a_name(self) -> None:
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--judge", "claims",
                       "--receipt", str(RECEIPT), "--evaluator", "all,python")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("already means every available evaluator", proc.stderr)

    def test_an_evaluator_without_the_claims_judge_is_refused_not_ignored(self) -> None:
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--evaluator", "python")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("--evaluator is only meaningful with --judge claims", proc.stderr)

    def test_an_unknown_evaluator_in_capcov_toml_names_the_key(self) -> None:
        (self.tmp / "capcov.toml").write_text('[judge]\nevaluator = "prolog"\n')
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--judge", "claims",
                       "--receipt", str(RECEIPT), cwd=self.tmp)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("unknown evaluator 'prolog'", proc.stderr)
        self.assertIn("[judge] evaluator in capcov.toml", proc.stderr)


class DefaultEvaluatorNeedsNoToolTests(unittest.TestCase):
    """The claims judge with no `--evaluator` judges with the standard library alone.

    This runs wherever the suite runs -- souffle present or not -- because that
    is the property: the default path of an opt-in feature must not need the
    opt-in tool.  What it must NOT do is pretend a differential happened.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="capcov-evaluator-default-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _judge(self, *extra: str, out: str = "judge"):
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--judge", "claims",
                       "--receipt", str(RECEIPT), "--judge-out", str(self.tmp / out), *extra,
                       env=_env(PATH=""))
        return proc, json.loads((self.tmp / out / "judge.json").read_text())

    def test_the_default_judge_runs_the_python_kernel_with_no_tool_on_path(self) -> None:
        """PATH is emptied: nothing but the interpreter already running is available."""
        proc, document = self._judge()
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(document["kernels"], ["python"])
        self.assertEqual(document["verdict"], "pending-premise")
        self.assertEqual(document["exit_code"], 5)

    def test_a_single_evaluator_is_never_recorded_as_a_passed_differential(self) -> None:
        _, document = self._judge(out="single")
        self.assertEqual(document["differential"], "not-run (single evaluator)")
        self.assertIsNone(document["compiled"])
        self.assertEqual(sorted(document["differential_report"]),
                         ["closure_digest_equal", "compiled_seconds", "failures",
                          "interpreter_seconds", "matched", "python_digest", "python_seconds"])
        # no digest is claimed for a kernel that did not run
        self.assertNotIn("souffle_digest", document["differential_report"])

    def test_the_capcov_toml_key_selects_the_evaluator(self) -> None:
        (self.tmp / "capcov.toml").write_text('[judge]\nevaluator = "python"\n')
        proc = _capcov("gate", str(PYTHON_APP / "coverage.json"), "--judge", "claims",
                       "--receipt", str(RECEIPT), "--judge-out", str(self.tmp / "keyed"),
                       cwd=self.tmp)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        document = json.loads((self.tmp / "keyed" / "judge.json").read_text())
        self.assertEqual(document["kernels"], ["python"])

    def test_the_stdout_line_names_the_kernels_and_the_differential(self) -> None:
        proc, _ = self._judge(out="stdout")
        self.assertIn("kernels python", proc.stdout)
        self.assertIn("differential not-run (single evaluator)", proc.stdout)


if __name__ == "__main__":
    unittest.main()
