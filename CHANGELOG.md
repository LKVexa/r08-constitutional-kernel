# Changelog — JY-S001-P001 r08-constitutional-kernel

## 0.1.2a1 — 2026-09-23 (security maintenance, partial candidate)

- Prevent boolean flags from bypassing string-based policy conditions; fully
  parse quoted operators and reject invalid short-circuit tails.
- Require non-empty, uniquely identified axioms and exact predicate nodes;
  validate signed bundles again on load and bound tree depth/expression size.
- Reject replayed proposals and authenticate both settlement signatures and
  the expected kernel digest during restart.
- Serialize state restoration and decisions across cooperating ledger instances.
  Preserve sticky degraded mode across instances and deep-copy nested state.
- Validate ledger sequence, repair valid unterminated rows, recover crash tails,
  and avoid applying state after a failed durable append.
- Validate coherence thresholds and distinct signing roles; reject malformed
  proposals and independent-verifier inputs cleanly.
- Add packaging, pinned CI, Apache 2.0 LICENSE and NOTICE naming
  RUSSELL PHILIP SMITHSON while preserving Microsoft MIT donor notices.

Validation: 23 inherited plus 20 security regression tests pass (43/43).
The PEP 440 alpha version preserves the existing partial-candidate status.
Existing valid ledger rows keep their format; replay now rejects unauthorized
or duplicate settlements. Key rotation and policy migration remain explicit
future work. See docs/AUDIT.md and SECURITY.md.

## 0.1.1-partial — 2026-09-14 (maintenance candidate, run-0001)
Baseline: 0.1.0-partial (build-0001, product.zip sha256 4edc6167…1690).
Compatible defect/security repairs only → patch increment (V-02).

- F1 evaluator (vendored donor, locally hardened with provenance kept):
  variable values were spliced literally into the expression text, so a
  benign quote or and/or keyword inside DATA (e.g. user "O'Brien")
  raised ExpressionError, was counted as an axiom violation, and drove
  the nucleus into sticky DEGRADED mode — a trivial denial-of-service
  through ordinary data. Values now substitute as opaque tokens compared
  as data; expression structure is fixed at parse time. The exact
  guarded values still refuse correctly.
- F2 ledger: a torn trailing line (crash tail) no longer makes the
  settlement ledger unloadable; it is truncated to the last durable
  entry.
- F3 ledger: the Merkle chain is verified at load; a tampered or
  mid-file corrupted ledger raises LedgerIntegrityError instead of
  loading silently.
- F4 nucleus: fail-closed DEGRADED mode and settled state now survive a
  process restart — both are rebuilt from the load-verified ledger. A
  reboot can no longer escape the sticky fail-closed state; recovery
  remains a human steward decision (unchanged, deliberately
  unimplemented).

Test alignment: the ledger tamper test now asserts the strengthened
load-time refusal. 18 baseline + 5 repair tests pass (23/23).
Rollback: build-0001 preserved unchanged; untampered ledgers load as-is.

## 0.1.0-partial — 2026-09-14 (build-0001, first run)
Initial partial candidate (kernel seal, P↔N handshake, coherence,
fail-closed degraded mode, atomic ledger).
