---
id: ADR-0011
type: adr
title: Keep analyzers and judges optional, with an unchanged default path
status: accepted
owner: capabilities
created: '2026-09-17T00:00:00.000Z'
updated: '2026-09-17T00:00:00.000Z'
tags: [adr, compatibility, cli, optional-tools]
summary: Existing invocations preserve upstream behavior; richer judging, evaluators, Shen and SCIP run only when explicitly requested.
---

## Context

The claims engine and analyzers add value to selected workflows, but importing
or requiring them by default would impose dependencies and change output for
all capcov users. The existing `--resolver scip` convention already makes
external analysis explicitly opt-in.

## Decision

Preserve the upstream no-flags behavior and lazy imports. Add named profiles:
`--judge four-cell|claims`, `--evaluator python|souffle|souffle-compiled`,
`--model shen:<dir>` with Stage D preflight, and `--static scip`. The claims
verdict is additive beside the four-cell result. Optional tools are detected
only when their profile is selected; missing tools produce a named actionable
unavailable/error result and never silently fall back to another authority.
Jev registration is lazy and remains advisory. Build extras and devShells must
state accurately which Python packages they install and which external
binaries remain caller-provided.

## Alternatives considered

- Making claims the default changes behavior and import/dependency surface for
  existing users.
- Automatically selecting any available kernel makes the same command behave
  differently across machines.
- Treating an empty package extra as if it installed an external executable is
  misleading; explicit checks and documentation are clearer.

## Consequences

The default-path compatibility test compares golden artifacts and import
behavior to the upstream baseline. Profiles need separate focused tests for
missing tools, explicit kernel choice and output composition. Packaging tests
must use an installed wheel rather than relying on the source tree. The
profiles do not weaken the semantics or authority boundaries of their
underlying evidence.

## Implementation state

On the optional-profile branch, the claims judge gate and evaluator selection
have focused reviews; the producer-profile name is present. The Shen model
preflight, static residue and scoped call-graph witness, lazy Jev registration,
wheel/import-hygiene proof, documentation and CI integration remain to be
completed. The stated verification is bounded: no-extras wheel install,
golden comparison, one regression run and one CI job, each with a ten-minute
integration-test ceiling. This ADR accepts the compatibility direction; it
does not claim the entire profile matrix is implemented.

## Evidence and limits

The optional branch head `d8cdeba` is based on upstream compatibility reference
`1b6a47a`. Public source entry points include
`packages/capabilities/src/capcov/claims/replay/judge.py`,
`packages/capabilities/src/capcov/claims/static/closure.py`, and
`packages/capabilities/tests/test_cli_judge.py`. The branch recorded a 672-test
upstream baseline. That historical result does not establish the unfinished
profile matrix: the no-extras wheel proof and CI job remain pending.
