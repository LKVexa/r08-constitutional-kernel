# R08 Constitutional Kernel

**0.1.2a1 — experimental partial implementation**

A local policy kernel for signed proposals, two-party authorization, durable
settlement, and sticky read-only degraded mode. Copyright 2026
**RUSSELL PHILIP SMITHSON**.

## Install and test

Requires Python 3.10 or later and cryptography. Validated locally with Python
3.12.14 and cryptography 50.0.1 on Windows.

```sh
python -m venv .venv
# Activate .venv for your shell.
python -m pip install -r requirements.txt
python -m pip install --no-deps .
python -m unittest discover -s tests -t . -v
```

The package import is `r08`; the distribution is `r08-constitutional-kernel`.
See [tests/test_r08.py](tests/test_r08.py) for a complete working fixture.

## How it works

1. A steward signs a non-empty set of uniquely identified policy axioms.
2. The constitutional kernel validates the bundle and checks its digest before
   each evaluation. Predicates support `all`, `any`, `not`, and conditions.
3. A proton signs a proposal containing its ID, intent, context and payload.
4. The nucleus evaluates the sealed policy and provisional coherence threshold.
5. A distinct neutron identity countersigns an authorization bound to the
   proposal and kernel. The ledger is committed before state changes are exposed.
6. Policy violations persist a sticky DEGRADED transition. Reads remain available;
   subsequent proposals are refused. Recovery is intentionally not implemented.

Condition expressions support comparisons `==` and `!=`, `and`/`or`,
quoted strings, and `{{dotted.variable}}` references. Boolean values normalize to
the strings `true`/`false`, matching existing policy literals. Structured,
missing and non-finite values fail closed. Entire expressions are parsed even
when a boolean branch would otherwise short-circuit.

## Maintenance improvements

The 0.1.2a1 release blocks proposal replay, authenticates settlements during
restart, serializes decisions across cooperating ledger instances, protects
nested state from mutation through reads, validates policy structure, and
rejects invalid thresholds. The parser now handles quoted operators correctly
and prevents boolean context values from bypassing string-based policy checks.

There are 43 tests: 23 inherited tests and 20 security regressions.
[docs/AUDIT.md](docs/AUDIT.md) documents findings and validation.

## Security limits

This is an API-level prototype, not an isolated security service. Python code
with access to its process can access keys or modify objects. The supplied
coherence metric and threshold are provisional; hardware anchoring, key
lifecycle governance, distributed quorum, recovery procedures and certification
remain unimplemented. No completion of the original 865-item master checklist
is claimed.

Protect the local ledger directory with OS permissions and Windows ACLs.
Merkle roots need an independent authenticated checkpoint to detect a complete
rewrite or valid suffix deletion. Network-filesystem locking and large-ledger
performance are unvalidated. Restart requires the same authorized keys and
kernel digest; migration and key rotation need an explicit future workflow.
See [SECURITY.md](SECURITY.md).

## Provenance and licensing

Derived from JY-S001-P001, 0.1.1-partial, run-0001. The supplied snapshot did
not include the historical STATUS_REPORT.md or full master checklist.

Original project code and September 2026 modifications are under the
[Apache License 2.0](LICENSE), copyright **RUSSELL PHILIP SMITHSON**.
The vendored expression evaluator and Merkle construction retain their
Microsoft MIT attribution. See [NOTICE](NOTICE) and
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
