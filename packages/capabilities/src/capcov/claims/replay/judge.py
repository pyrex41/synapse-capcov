"""Judge a replay receipt directory: the driver behind ``--judge claims``.

This is the production half of what ``scripts/compiled_checker.py`` has always
done -- build the receipt's combined bundle (``replay.join.build``), run the
kernels, certify every claim row, and turn the closure into a verdict, an exit
code and a ``judge.json``.  It lives in ``src`` rather than in the script so the
CLI's ``--judge claims`` path and the script judge the same way, from the same
code, and so neither has to import from ``tests/`` or ``scripts/``.

Nothing here is reachable from ``capcov.cli`` unless a caller asked for the
claims judge: ``capcov.cli`` imports this module lazily, inside the branch that
``--judge claims`` (or ``[judge] engine = "claims"``) selects.

Exit codes are the script's, unchanged, because the producer repo's build gates
on them::

    0  every op the verdict turns on is op_qualified supported/complete
    1  an op is not supported, not complete, or was not replayed at all
    2  the kernels disagree, or the compiled kernel could not be built
    3  the receipt does not meet the exporter's contract (a contract finding)
    4  the toolchain or the judge's own environment is unavailable
    5  every op the verdict turns on is *pending* a premise nothing can satisfy
       yet -- today only the Stage D typed-checker certificate

``capcov reconcile``/``capcov gate`` collapse those to a pass/fail (0 or 1) and
write the full code into ``judge.json``; the script returns them directly.

The Souffle interpreter is a **precondition** of judging, not a fallback:
``require_tools`` raises ``JudgeToolsUnavailable`` naming the missing binary,
the same shape ``capcov discover --resolver scip`` uses for a missing indexer.
Degrading to the Python kernel alone would hand back a differential of one.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

from .. import canonical_json, souffle
from ..souffle import compile as compiled
from . import join as replay_join
from . import pack as replay_pack
from . import replay_facts

JUDGE_SCHEMA = "capcov-compiled-judge-v1"
JUDGE_FILE = "judge.json"
DEFAULT_CACHE_DIR = Path(os.environ.get("CAPCOV_SOUFFLE_CACHE_DIR")
                         or Path.home() / ".cache" / "capcov" / "souffle-compiled")

EXIT_OK = 0
EXIT_NOT_SUPPORTED = 1
EXIT_KERNEL = 2
EXIT_CONTRACT = 3
EXIT_UNAVAILABLE = 4
EXIT_PENDING_PREMISE = 5

VERDICT_SUPPORTED = "supported"
VERDICT_NOT_SUPPORTED = "not-supported"
VERDICT_PENDING_PREMISE = "pending-premise"
VERDICT_KERNEL_MISMATCH = "kernel-mismatch"
VERDICT_CONTRACT_FINDING = "contract-finding"
VERDICT_UNAVAILABLE = "unavailable"

#: the verdicts that are only reachable once the kernels agreed and the rows
#: were certified -- i.e. the receipt was actually judged
JUDGED_VERDICTS = (VERDICT_SUPPORTED, VERDICT_NOT_SUPPORTED, VERDICT_PENDING_PREMISE)

SOUFFLE_INSTALL_HINT = (
    "install Souffle 2.5 (https://souffle-lang.github.io/install) or enter the "
    "pinned devShell with `nix develop`"
)


#: What a receipt that does not meet the exporter's contract raises out of
#: ``judge_receipt`` (a malformed relation file, unreadable JSON).  Named here so
#: a caller can report it as a finding about the evidence without importing the
#: exporter.
ReceiptContractFinding = (replay_facts.ExportInputError, json.JSONDecodeError)


class JudgeToolsUnavailable(RuntimeError):
    """An external binary the claims judge needs is not present.

    The sibling of ``capcov.scip.resolve.ScipToolsUnavailable``: raised before
    any work is done, naming the tool and how to install it, so a caller that
    asked for the claims judge gets a reason rather than a degraded answer.
    """


def tools_available(executable: str = "souffle") -> bool:
    """True when the Souffle interpreter the differential needs resolves. Runs nothing."""
    return shutil.which(executable) is not None


def require_tools(executable: str = "souffle") -> None:
    """Raise ``JudgeToolsUnavailable`` naming ``executable`` when it is not on PATH."""
    if not tools_available(executable):
        raise JudgeToolsUnavailable(
            f"the claims judge needs the Souffle interpreter {executable!r}, which is "
            f"not on PATH. Install it with: {SOUFFLE_INSTALL_HINT}"
        )


def sha256_json(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def op_entry(join: replay_join.ReplayJoin, summary: dict[str, Any], op: str) -> dict[str, Any]:
    verdict = join.verdict(join.claim_id("qualified", op)) or {}
    entry = summary.get(op, {})
    certificate = join.certificates.get(join.claim_id("qualified", op))
    qualified = {
        "semantic": verdict.get("semantic"),
        "operational": verdict.get("operational"),
        "missing_premises": entry.get("missing_premise", []),
    }
    return {
        # the per-op answer in one word, so a caller need not re-derive it from
        # the pair; VERDICT_SUPPORTED only when the op is supported *and* complete
        "verdict": (VERDICT_SUPPORTED if qualified["semantic"] == "supported"
                    and qualified["operational"] == "complete" else VERDICT_NOT_SUPPORTED),
        # "qualified" / "pending <relation>" / "unsupported" (replay.join.qualification):
        # a pending op passed every premise that is checkable today
        "qualification": entry.get("qualification", replay_join.QUALIFICATION_UNSUPPORTED),
        "op_qualified": qualified,
        "corpus_constrains": bool(entry.get("corpus_constrains")),
        # the cross-request gate op_qualified_rt is now bound by: the repeats of this op's
        # requests, the violations found among them, and the targets judged not-found
        "repeat_delete": entry.get("repeat_delete", {"repeats": [], "violations": [], "not_found": []}),
        # the learn campaign, when one is bound to the run: whether the model's predictions
        # matched the oracle for this op, and whether the campaign says the op is unmodelled
        "learn_consistent": entry.get("learn_consistent"),
        "learn_unmodeled": bool(entry.get("learn_unmodeled")),
        "exclusions_applied": list(entry.get("exclusions_applied", [])),
        "blocking_premise": entry.get("blocking_premise"),
        "certificate_sha256": sha256_json(certificate) if certificate is not None else None,
    }


def judge_document(join: replay_join.ReplayJoin, required: list[str], *,
                   verdict: str, exit_code: int, program_digest: str | None,
                   findings: list[str]) -> dict[str, Any]:
    receipt = join.receipt
    document: dict[str, Any] = {
        "schema": JUDGE_SCHEMA,
        "receipt": {"run": join.run, "model": receipt.get("model"), "nonce": receipt.get("nonce"),
                    "snapshot": receipt.get("snapshot"), "php_commit": receipt.get("php_commit"),
                    "go_commit": receipt.get("go_commit")},
        "pack": {"id": replay_pack.PACK_ID, "program_digest": program_digest,
                 "relation_count": len(join.bundle.relations) if join.bundle is not None else 0,
                 "rule_count": len(join.bundle.rules) if join.bundle is not None else 0},
        "compiled": join.checker.provenance() if join.checker is not None else None,
        "kernels": None,
        "ops": {},
        "required_ops": list(required),
        "learn": {"present": False},
        "contract_findings": list(findings),
        "verdict": verdict,
        "exit_code": exit_code,
    }
    outcome = join.result if join.result is not None else join.mismatch
    if outcome is not None:
        timings = dict(getattr(outcome, "timings", ()))
        document["kernels"] = {
            "matched": join.result is not None and join.result.matched,
            "python_digest": outcome.python.canonical_digest,
            "souffle_digest": outcome.souffle.canonical_digest,
            "compiled_digest": getattr(outcome, "compiled", None) and outcome.compiled.canonical_digest,
            "closure_digest_equal": getattr(outcome, "closure_digest_equal", False),
            "interpreter_seconds": round(timings.get("souffle", 0.0), 3),
            "compiled_seconds": round(timings.get("souffle-compiled", 0.0), 3),
            "python_seconds": round(timings.get("python", 0.0), 3),
            "failures": {report.backend: report.operational_failure
                         for report in (outcome.python, outcome.souffle,
                                        getattr(outcome, "compiled", None))
                         if report is not None and report.operational_failure},
        }
    if join.result is not None:
        summary = replay_join.summary(join)
        document["ops"] = {op: op_entry(join, summary, op) for op in join.ops}
        document["learn"] = summary.get("learn", {"present": False})
    return document


def op_is_supported(entry: dict[str, Any]) -> bool:
    return entry["verdict"] == VERDICT_SUPPORTED


def all_pending(replayed: dict[str, Any], unmet: list[str]) -> bool:
    """Every unmet op is blocked only by a premise nothing can satisfy yet.

    A required op that was never replayed has no entry and is never pending: it
    is an unmet requirement about this receipt, which exit 1 is for.
    """
    return bool(unmet) and all(
        str(replayed.get(op, {}).get("qualification", "")).startswith("pending ") for op in unmet)


def unmet_ops(replayed: dict[str, Any], required: list[str]) -> list[str]:
    """The ops the verdict turns on that are not op_qualified supported/complete.

    With ``--require-op`` those are exactly the required ops (an op that was
    never replayed is unmet).  With none, the verdict is derived from every
    replayed op instead of from an empty requirement: ``supported`` over zero
    requirements is a vacuous truth no party has asserted, and a caller that
    reads ``.verdict`` would take it for a positive judgement of the receipt.
    """
    if required:
        return [op for op in required if op not in replayed or not op_is_supported(replayed[op])]
    return [op for op in sorted(replayed) if not op_is_supported(replayed[op])]


def read_join(receipt_dir: Path) -> replay_join.ReplayJoin:
    """Build the join; the receipt's own I/O errors are the receipt's contract.

    Only a read of the receipt directory maps OSError to a contract finding.
    The judge's own I/O (its cache, its output directory) stays an environment
    failure, so an unwritable disk is never reported as a finding against the
    receipt.
    """
    try:
        return replay_join.build(receipt_dir)
    except OSError as exc:
        raise replay_facts.ExportInputError(
            f"receipt directory could not be read: {receipt_dir}: {exc}") from exc


def summary_lines(document: dict[str, Any]) -> list[str]:
    """The judged-path stdout: one line per op, then the run's verdict line."""
    lines = [
        f"{op}: {entry['qualification']} op_qualified={entry['op_qualified']['semantic']}"
        f"/{entry['op_qualified']['operational']}"
        f" missing={entry['op_qualified']['missing_premises']}"
        f" exclusions={entry['exclusions_applied']}"
        for op, entry in sorted(document["ops"].items())
    ]
    binary = document["compiled"]["binary_sha256"] if document["compiled"] else "-"
    lines.append(f"verdict={document['verdict']} kernels_matched={document['kernels']['matched']}"
                 f" binary={binary[:12]}")
    return lines


def judge_receipt(receipt_dir: Path, out_dir: Path, required: list[str], *,
                  kernels: str = "two", cache_dir: str | Path = DEFAULT_CACHE_DIR,
                  executable: str = "souffle") -> tuple[dict[str, Any], list[str]]:
    """Judge ``receipt_dir``, write ``judge.json`` under ``out_dir``, print nothing.

    Returns ``(document, diagnostics)``: the judge document (whose ``exit_code``
    is the answer) and the lines a caller writes to stderr.  Printing is the
    caller's, because the CLI and the script address different readers; the
    judgement is not.

    ``kernels="two"`` is python vs the Souffle interpreter -- what the CLI runs,
    since a compiled kernel would make the judge depend on a C++ toolchain as
    well.  ``kernels="three"`` adds the compiled checker, which is what the
    cross-repo script gates on.
    """
    receipt_dir = Path(receipt_dir)
    out_dir = Path(out_dir)
    diagnostics: list[str] = []
    join = read_join(receipt_dir)
    if join.bundle is None:
        document = judge_document(join, required, verdict=VERDICT_CONTRACT_FINDING,
                                  exit_code=EXIT_CONTRACT, program_digest=None,
                                  findings=join.contract_findings)
        out_dir.mkdir(parents=True, exist_ok=True)
        write_json(out_dir / JUDGE_FILE, document)
        diagnostics.extend(f"contract finding: {finding}" for finding in join.contract_findings)
        return document, diagnostics
    program_digest = souffle.program_for_pack(join.bundle).program_digest
    try:
        join = replay_join.evaluate_join(join, str(out_dir / "differential"), kernels=kernels,
                                         cache_dir=cache_dir, executable=executable)
    except souffle.SouffleUnavailable as exc:
        document = judge_document(join, required, verdict=VERDICT_UNAVAILABLE,
                                  exit_code=EXIT_UNAVAILABLE, program_digest=program_digest,
                                  findings=join.contract_findings)
        document["message"] = str(exc)
        write_json(out_dir / JUDGE_FILE, document)
        diagnostics.append(f"toolchain unavailable: {exc}")
        return document, diagnostics
    except compiled.CompileError as exc:
        document = judge_document(join, required, verdict=VERDICT_KERNEL_MISMATCH,
                                  exit_code=EXIT_KERNEL, program_digest=program_digest,
                                  findings=join.contract_findings)
        document["message"] = str(exc)[-4000:]
        write_json(out_dir / JUDGE_FILE, document)
        diagnostics.append(f"compile failed: {str(exc)[-400:]}")
        return document, diagnostics
    except AssertionError as exc:
        # the kernels agreed on the closure but not on a claim row, a
        # certificate or a recheck: still a kernel disagreement, never a verdict
        document = judge_document(join, required, verdict=VERDICT_KERNEL_MISMATCH,
                                  exit_code=EXIT_KERNEL, program_digest=program_digest,
                                  findings=join.contract_findings)
        document["message"] = str(exc)[-4000:]
        write_json(out_dir / JUDGE_FILE, document)
        diagnostics.append(f"kernels disagree on a certified claim row: {exc}")
        return document, diagnostics
    if join.mismatch is not None:
        document = judge_document(join, required, verdict=VERDICT_KERNEL_MISMATCH,
                                  exit_code=EXIT_KERNEL, program_digest=program_digest,
                                  findings=join.contract_findings)
        write_json(out_dir / JUDGE_FILE, document)
        diagnostics.append("claim kernels disagree; the receipt is not judged")
        return document, diagnostics
    replay_join.write_artifacts(join, out_dir)
    document = judge_document(join, required, verdict=VERDICT_SUPPORTED, exit_code=EXIT_OK,
                              program_digest=program_digest, findings=join.contract_findings)
    unmet = unmet_ops(document["ops"], required)
    judged = required or sorted(document["ops"])
    if unmet or not judged:
        document["verdict"] = VERDICT_NOT_SUPPORTED
        document["exit_code"] = EXIT_NOT_SUPPORTED
        document["unmet_ops"] = unmet
        if not judged:
            document["message"] = "no op was replayed and none was required; nothing is supported"
        elif all_pending(document["ops"], unmet):
            # every unmet op is blocked only by a premise nothing can satisfy yet
            document["verdict"] = VERDICT_PENDING_PREMISE
            document["exit_code"] = EXIT_PENDING_PREMISE
            document["pending_ops"] = list(unmet)
            document["message"] = ("pending, not unsupported: " + ", ".join(
                f"{op} is {document['ops'][op]['qualification']}" for op in unmet))
    write_json(out_dir / JUDGE_FILE, document)
    if unmet and document["verdict"] == VERDICT_PENDING_PREMISE:
        diagnostics.append(document["message"])
    elif unmet:
        label = "required" if required else "replayed"
        diagnostics.append(f"{label} ops not supported: {', '.join(unmet)}")
    elif not judged:
        diagnostics.append(document["message"])
    return document, diagnostics


__all__ = ["JUDGE_FILE", "JUDGE_SCHEMA", "DEFAULT_CACHE_DIR", "JUDGED_VERDICTS",
           "EXIT_OK", "EXIT_NOT_SUPPORTED", "EXIT_KERNEL", "EXIT_CONTRACT",
           "EXIT_UNAVAILABLE", "EXIT_PENDING_PREMISE", "VERDICT_SUPPORTED",
           "VERDICT_NOT_SUPPORTED", "VERDICT_PENDING_PREMISE", "VERDICT_KERNEL_MISMATCH",
           "VERDICT_CONTRACT_FINDING", "VERDICT_UNAVAILABLE", "JudgeToolsUnavailable",
           "ReceiptContractFinding", "tools_available", "require_tools", "sha256_json",
           "write_json", "op_entry",
           "judge_document", "op_is_supported", "all_pending", "unmet_ops", "read_join",
           "summary_lines", "judge_receipt"]
