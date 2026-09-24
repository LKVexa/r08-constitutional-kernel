"""R08 Constitutional Kernel (K) — sealed, read-only predicate trees.

Source invariant 1 (Controlling Source v2.0.0 §1): safety axioms and
non-delegable boundaries are compiled into cryptographically sealed
formal predicate trees, strictly read-only and immune to in-context
modification, prompt injection, heuristic override, or cognitive drift.

This build seals the compiled axiom bundle with SHA-256 digesting plus an
Ed25519 steward signature over the canonical bytes; the kernel refuses to
load any bundle whose bytes, digest, or signature do not verify, and the
loaded object exposes evaluation only — there is no mutation API, and
tampering with the in-memory tree is detected at every evaluation by
digest re-verification. Hardware anchoring (TPM 2.0 / secure enclave) is
a recorded BLOCKED item (AF-07 platform profile decision), not claimed.

Predicate trees: nodes are all/any/not combinators over leaf conditions.
Leaf conditions use the eval()-free condition evaluator retrieved from
the GitHub Junkyard donor amplifier-collection-recipes (MIT, vendored) —
a proven chop-shop fit — over the ProposalEnvelope's context fields.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

from .vendor.condition_evaluator import ExpressionError, evaluate_condition


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(obj_or_bytes) -> str:
    b = obj_or_bytes if isinstance(obj_or_bytes, (bytes, bytearray)) \
        else canonical_bytes(obj_or_bytes)
    return "sha256:" + hashlib.sha256(b).hexdigest()


class KernelError(Exception):
    pass


class SealViolation(KernelError):
    """The sealed bundle failed digest or signature verification."""


_NODE_KEYS = {"all", "any", "not", "condition"}


def _validate_tree(node: dict, path: str = "root", depth=0) -> None:
    if depth > 64 or not isinstance(node, dict) or len(node) != 1:
        raise KernelError("invalid or excessively deep predicate tree")
    keys = set(node) & _NODE_KEYS
    if len(keys) != 1:
        raise KernelError(f"predicate node at {path} must have exactly one of {_NODE_KEYS}")
    k = keys.pop()
    if k in ("all", "any"):
        children = node[k]
        if not isinstance(children, list) or not children:
            raise KernelError(f"{path}.{k} must be a non-empty list")
        for i, c in enumerate(children):
            _validate_tree(c, f"{path}.{k}[{i}]", depth+1)
    elif k == "not":
        _validate_tree(node["not"], f"{path}.not", depth+1)
    else:
        if not isinstance(node["condition"], str) or not node["condition"].strip():
            raise KernelError(f"{path}.condition must be a non-empty string")


def _validate_axioms(axioms, version):
    if not isinstance(version, str) or not version.strip():
        raise KernelError("kernel version must be a non-empty string")
    if not isinstance(axioms, list) or not axioms or len(axioms) > 4096:
        raise KernelError("a kernel requires 1..4096 axioms")
    identifiers = set()
    for ax in axioms:
        if not isinstance(ax, dict) or set(ax) != {"axiom_id", "title", "severity", "predicate"}:
            raise KernelError("axiom fields must be axiom_id/title/severity/predicate")
        if ax["severity"] not in ("critical", "high", "medium"):
            raise KernelError("severity must be critical|high|medium")
        if not isinstance(ax["axiom_id"], str) or not ax["axiom_id"].strip() \
                or ax["axiom_id"] in identifiers or not isinstance(ax["title"], str):
            raise KernelError("axiom identifiers must be non-empty and unique")
        identifiers.add(ax["axiom_id"])
        _validate_tree(ax["predicate"], ax["axiom_id"])


def compile_bundle(axioms: list, steward_key: Ed25519PrivateKey,
                   version: str) -> dict:
    """Compile and sign a non-empty validated steward policy."""
    _validate_axioms(axioms, version)
    body = {"schema": "r08/kernel-bundle/v1", "version": version,
            "axioms": axioms}
    payload = canonical_bytes(body)
    return {
        "body": body,
        "bundle_digest": digest(payload),
        "steward_signature": steward_key.sign(payload).hex(),
    }


class ConstitutionalKernel:
    """Loaded, sealed, evaluation-only kernel."""

    def __init__(self, sealed_bundle: dict, steward_pub: Ed25519PublicKey):
        if not isinstance(sealed_bundle, dict):
            raise SealViolation("invalid sealed bundle")
        body = sealed_bundle.get("body")
        if not isinstance(body, dict):
            raise SealViolation("invalid kernel body")
        payload = canonical_bytes(body)
        if digest(payload) != sealed_bundle.get("bundle_digest"):
            raise SealViolation("bundle digest mismatch")
        try:
            steward_pub.verify(bytes.fromhex(sealed_bundle["steward_signature"]),
                               payload)
        except (InvalidSignature, KeyError, ValueError) as exc:
            raise SealViolation("steward signature verification failed") from exc
        if body.get("schema") != "r08/kernel-bundle/v1":
            raise SealViolation("unknown kernel bundle schema")
        if set(body) != {"schema", "version", "axioms"}:
            raise SealViolation("invalid kernel body fields")
        _validate_axioms(body["axioms"], body["version"])
        # Deep-freeze via a private canonical snapshot; every evaluation
        # re-verifies the live tree against the sealed digest, so an
        # in-process mutation of the tree is detected, not silently used.
        self._body = json.loads(payload.decode())
        self._sealed_digest = sealed_bundle["bundle_digest"]

    @property
    def version(self) -> str:
        return self._body["version"]

    @property
    def bundle_digest(self) -> str:
        return self._sealed_digest

    def _check_seal(self) -> None:
        if digest(canonical_bytes(self._body)) != self._sealed_digest:
            raise SealViolation("in-memory kernel no longer matches its seal")

    def evaluate(self, context: dict[str, Any]) -> dict:
        """Evaluate every axiom against a proposal context. Returns
        per-axiom results and an overall verdict. Any evaluation error on
        a critical/high axiom is a violation (fail closed), never a pass."""
        self._check_seal()
        results = []
        violations = []
        for ax in self._body["axioms"]:
            try:
                ok = self._eval_node(ax["predicate"], context)
                status = "satisfied" if ok else "violated"
            except ExpressionError as exc:
                ok = False
                status = f"error: {exc}"
            results.append({"axiom_id": ax["axiom_id"], "severity": ax["severity"],
                            "status": status})
            if not ok:
                violations.append(ax["axiom_id"])
        return {"kernel_version": self.version,
                "bundle_digest": self._sealed_digest,
                "results": results, "violations": violations,
                "verdict": "PASS" if not violations else "VIOLATION"}

    def _eval_node(self, node: dict, context: dict) -> bool:
        if "all" in node:
            return all(self._eval_node(c, context) for c in node["all"])
        if "any" in node:
            return any(self._eval_node(c, context) for c in node["any"])
        if "not" in node:
            return not self._eval_node(node["not"], context)
        return evaluate_condition(node["condition"], context)
