# Audit: R08 Constitutional Kernel 0.1.2a1

Date: 2026-09-23. Source: JY-S001-P001 / 0.1.1-partial / run-0001 / product.
The original delivery directory is preserved; this release is a separate working copy.

## Scope

Reviewed all original Python modules, the vendored evaluator and inherited tests.
The baseline passed 23 tests. Fifteen new regression methods reproduced defects,
with 19 failed assertions and 6 errors across subtests. Five further tests cover
failed writes, distinct signing roles, concurrent replay, empty ledgers and
invalid condition values. The complete suite passes 43 tests.

| Finding | Repair |
| --- | --- |
| Boolean tool flag bypassed a string-based approval predicate | Normalize booleans consistently |
| Shallow state copies exposed nested state to mutation | Deep snapshots on proposal and read boundaries |
| Signed proposals could settle repeatedly | Durable proposal-ID replay rejection |
| Restart trusted settlement payloads without authenticating signatures | Verify both signatures and kernel binding on replay |
| A stale instance could ignore another instance's degraded transition | Restore and decide under one ledger transaction |
| Multiple ledger handles could corrupt the chain | Lock cooperating local writers and reload |
| Ledger sequence was not checked | Strict schema, sequence and Merkle verification |
| Unterminated complete row broke the following append | Validate then repair its newline |
| Empty or duplicate axiom sets were accepted | Require non-empty unique axiom IDs |
| Unknown predicate keys were ignored | Validate exact node fields and depth |
| Signed malformed bundles bypassed compiler validation on load | Validate loaded bundle structure |
| Quoted operators changed expression structure | Tokenize and parse quoted literals correctly |
| Short-circuiting hid malformed expression tails | Parse and validate the complete expression |
| NaN/out-of-range coherence thresholds were accepted | Require a finite threshold in [0,1] |
| Malformed settlement structures raised uncontrolled exceptions | Return false from independent verification |

## Validation and publication

- 43/43 tests pass locally on Windows/Python 3.12.14/cryptography 50.0.1.
- Source syntax, JSON, TOML, version alignment and licensing files validated.
- Built distribution and its installed test run are recorded in the delivery report.
- Credentials and generated keys are excluded from the publication source.
- CI covers Linux Python 3.10/3.12/3.14 and Windows Python 3.12.
- No dedicated vulnerability-database scanner was run locally.

The parser adaptation is a prominent local modification to the MIT donor;
upstream licenses are retained. Original code and permitted modifications
carry Apache 2.0 licensing and RUSSELL PHILIP SMITHSON attribution.

## Limits

See SECURITY.md. This audit does not certify the original master checklist,
isolate arbitrary Python code, establish hardware trust, define governance,
or implement distributed transactions. Existing valid ledger row format is
retained; replay now rejects unauthorized or duplicate settlements.
The expected kernel digest must remain consistent across replay.

Dependency version was checked against
[cryptography on PyPI](https://pypi.org/project/cryptography/).
Pinned workflow actions are the official
[checkout 6.0.2](https://github.com/actions/checkout/releases/tag/v6.0.2) and
[setup-python 6.2.0](https://github.com/actions/setup-python/releases/tag/v6.2.0).
