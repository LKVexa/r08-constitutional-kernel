# Third-party notices — JY-S001-P001

## amplifier-collection-recipes (GitHub Junkyard donor — reused fit)
- Donor car: `D:\desktop\GitHub Junkyard\amplifier-collection-recipes` (working tree).
- License: MIT (Microsoft Corporation); full text in `r08/vendor/LICENSE.amplifier-collection-recipes.txt`.
- Part: `expression_evaluator.py` vendored as `r08/vendor/condition_evaluator.py` —
  the eval()-free leaf-condition evaluator inside the constitutional predicate
  trees. Fit first proven in job JY-S020-P001.

## merklecpp (GitHub Junkyard donor — reused fit)
- Donor car: `D:\desktop\GitHub Junkyard\merklecpp` (working tree).
- License: MIT (Microsoft Corporation); full text in `r08/vendor/LICENSE.merklecpp.txt`.
- Reuse: the atomic settlement ledger (`r08/nucleus.py`) uses the donor's Merkle
  scheme, first proven in job JY-S021-P001.

## Host libraries
- `cryptography` (Apache-2.0/BSD) supplies Ed25519 — build-environment dependency.

## Negative retrieval results (for the ledger)
- No policy-engine / predicate-tree / constitutional-kernel donor exists in the
  yard (searched: policy engine constraint evaluation, state machine) —
  `build-new: sealed predicate-tree kernel, P<->N handshake, coherence scorer,
  fail-closed mode (searched: policy engine, state machine, dsse/attestation
  from prior jobs)`.


Local modification (0.1.1-partial): r08/vendor/condition_evaluator.py
(amplifier-collection-recipes donor, MIT) hardened in place — variable
substitution now uses opaque tokens instead of literal splicing. Donor
provenance and license retained; diff recorded in audit/UPGRADE_RECORD.json.

Local modification (0.1.2a1, 2026-09-23): the condition evaluator now uses a
bounded lexer and full parser, preserves quoted operators as data, normalizes
boolean flags consistently, and rejects malformed trailing syntax. Copyright
2026 RUSSELL PHILIP SMITHSON for these modifications; original Microsoft MIT
attribution and license are retained. See docs/AUDIT.md and CHANGELOG.md.
