"""With no flag and no optional tool, this branch reproduces upstream main byte for byte.

`fixtures/upstream_golden/` was produced by upstream main (commit 1b6a47a) from
a separate read-only checkout, with the optional toolchain hidden from PATH and
no extras installed -- see its README.md.  This test replays the same
`generate.py` against THIS tree, through the same `normalize.py`, and requires
the result to be identical.  It is the assertion the whole optional-profiles
direction rests on: every addition is reachable only through an explicit flag or
a capcov.toml key, so the default path is not ours to move.

What is compared: `discover` on the go fixture (which needs an extra it does not
have, and says so), the full `discover -> observe -> reconcile -> gate -> report`
pipeline on the python fixture, `discover` on an OpenAPI document, `flows
coverage`/`gate`, `features validate`, and every `--help`.  Artifacts, stdout,
and exit codes, all byte-identical after the golden's own `<root>`/timestamp
normalization.

Two documented exceptions, each with its own test rather than a silent skip:

* **The last line of a failing run, not its traceback.**  `normalize.py` writes
  a `.error_line` beside every non-empty `.stderr` precisely because the frames
  above it carry `cli.py` line numbers that move with any edit.  The `.stderr`
  files that have an `.error_line` are compared through it; the rest are
  compared whole.
* **`reconcile --help` and `gate --help` list the new opt-in flags.**  A flag
  that exists appears in its command's help -- upstream's own
  `discover --help` lists `--resolver` for exactly this reason.
  `test_reconcile_and_gate_help_gains_only_the_judge_flags` pins the delta to
  exactly `--judge`, `--receipt`, `--judge-out`: no upstream option lost, no
  fourth option gained.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).resolve().parent / "fixtures" / "upstream_golden"
GENERATE = GOLDEN / "generate.py"
NORMALIZE = GOLDEN / "normalize.py"
META = {"README.md", "MANIFEST.json", "generate.py", "normalize.py"}
# the two commands that gained the opt-in --judge flags; pinned by their own test
HELP_WITH_JUDGE = {"cli/help_reconcile.stdout", "cli/help_gate.stdout"}
JUDGE_FLAGS = {"--judge", "--receipt", "--judge-out"}


def _hidden_path() -> str:
    """The golden's PATH: this interpreter's bindir first, then the system dirs.

    No indexer, no souffle, no go, no node -- whatever is installed on the host,
    the run under test cannot see it.  The interpreter's own bindir goes first so
    `python3` is not the macOS system 3.9.
    """
    return os.pathsep.join([str(Path(sys.executable).parent), "/usr/bin", "/bin",
                            "/usr/sbin", "/sbin"])


def _options(help_text: str) -> set[str]:
    """Every long option argparse printed, regardless of how it wrapped the column."""
    return {token.rstrip(",")
            for token in help_text.replace("\n", " ").split()
            if token.startswith("--") and len(token) > 2}


class UpstreamGoldenTests(unittest.TestCase):
    """One generate+normalize for the whole class; the comparisons are pure."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace = Path(tempfile.mkdtemp(prefix="capcov-golden-"))
        raw, cls.actual = cls.workspace / "raw", cls.workspace / "normalized"
        env = {
            "PATH": _hidden_path(),
            "HOME": os.environ.get("HOME", str(cls.workspace)),
            "TERM": "dumb",
            "LANG": "en_US.UTF-8",
            "PYTHONPATH": os.pathsep.join([str(PACKAGE_ROOT / "src"), str(PACKAGE_ROOT)]),
            "CAPCOV_CAP_ROOT": str(PACKAGE_ROOT),
        }
        generated = subprocess.run([sys.executable, str(GENERATE), str(raw)],
                                   cwd=str(PACKAGE_ROOT), env=env, text=True,
                                   capture_output=True)
        assert generated.returncode == 0, generated.stdout + generated.stderr
        normalized = subprocess.run(
            [sys.executable, str(NORMALIZE), str(raw), str(cls.actual),
             f"{raw / '_work'}=<root>", f"{raw}=<out>",
             f"{PACKAGE_ROOT}=<upstream>/packages/capabilities",
             f"{env['HOME']}=<home>"],
            text=True, capture_output=True)
        assert normalized.returncode == 0, normalized.stdout + normalized.stderr

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.workspace, ignore_errors=True)

    def _relative_golden_files(self) -> list[str]:
        return sorted(
            str(path.relative_to(GOLDEN)) for path in GOLDEN.rglob("*")
            if path.is_file() and path.name not in META
            and not str(path.relative_to(GOLDEN)).startswith("suite/"))

    def test_the_golden_bytes_are_the_ones_the_manifest_names(self) -> None:
        """Prove the comparison below read upstream's committed bytes, not a re-baseline."""
        manifest = json.loads((GOLDEN / "MANIFEST.json").read_text())["sha256"]
        drifted = {
            name: hashlib.sha256((GOLDEN / name).read_bytes()).hexdigest()
            for name in self._relative_golden_files()
            if name in manifest
            and hashlib.sha256((GOLDEN / name).read_bytes()).hexdigest() != manifest[name]}
        self.assertEqual(drifted, {})
        self.assertEqual(set(self._relative_golden_files()) - set(manifest), set())

    def test_every_default_path_artifact_is_byte_identical_to_upstream(self) -> None:
        differing, missing = [], []
        for name in self._relative_golden_files():
            if name in HELP_WITH_JUDGE:
                continue
            if name.endswith(".stderr") and (GOLDEN / name).with_suffix(".error_line").is_file():
                continue  # compared through .error_line; see the module docstring
            produced = self.actual / name
            if not produced.is_file():
                missing.append(name)
                continue
            if produced.read_bytes() != (GOLDEN / name).read_bytes():
                differing.append(name)
        self.assertEqual(missing, [], "our branch produced no counterpart for these")
        self.assertEqual(differing, [], "our branch moved upstream's default path here")

    def test_our_run_produced_no_artifact_upstream_did_not(self) -> None:
        upstream = set(self._relative_golden_files())
        ours = {str(path.relative_to(self.actual))
                for path in self.actual.rglob("*") if path.is_file()}
        self.assertEqual(sorted(ours - upstream), [])

    def test_the_final_message_of_every_failing_run_is_unchanged(self) -> None:
        """The stable half of a failing run: the last line, not the frames above it."""
        lines = [name for name in self._relative_golden_files() if name.endswith(".error_line")]
        self.assertTrue(lines, "the golden pins at least one failing run")
        for name in lines:
            with self.subTest(name):
                self.assertEqual((self.actual / name).read_bytes(),
                                 (GOLDEN / name).read_bytes())

    def test_reconcile_and_gate_help_gains_only_the_judge_flags(self) -> None:
        """The one allowed delta, and it is exactly three opt-in flags wide."""
        for name in sorted(HELP_WITH_JUDGE):
            with self.subTest(name):
                upstream = _options((GOLDEN / name).read_text())
                ours = _options((self.actual / name).read_text())
                self.assertEqual(ours - upstream, JUDGE_FLAGS)
                self.assertEqual(upstream - ours, set(),
                                 "no upstream option may disappear")
                exit_name = name.replace(".stdout", ".exit")
                self.assertEqual((self.actual / exit_name).read_bytes(),
                                 (GOLDEN / exit_name).read_bytes())

    def test_no_other_help_text_moved(self) -> None:
        """`capcov --help` still lists upstream's subcommands and no experiment namespace."""
        top = (self.actual / "cli" / "help.stdout").read_text()
        self.assertEqual(top, (GOLDEN / "cli" / "help.stdout").read_text())
        self.assertNotIn("experiment", top)
        self.assertNotIn("claims", top)


if __name__ == "__main__":
    unittest.main()
