import copy
import json
import math
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from r08.kernel import ConstitutionalKernel, KernelError, SealViolation, canonical_bytes, compile_bundle, digest
from r08.nucleus import AtomicLedger, Nucleus, HandshakeError, LedgerIntegrityError, DegradedMode, make_proposal, verify_settlement_record
from r08.coherence import coherence_verdict
from r08.vendor.condition_evaluator import ExpressionError, evaluate_condition
from tests.test_r08 import build_system, BASE_CTX, AXIOMS


class Security(unittest.TestCase):
    def test_boolean_tool_flag_cannot_bypass_approval(self):
        _, _, _, n, p, *_ = build_system()
        result = n.submit(make_proposal(p, "tool", dict(BASE_CTX, uses_external_tool=True), {}))
        self.assertEqual(result["decision"], "REFUSED_FAIL_CLOSED")

    def test_nested_state_is_not_mutable_through_reads(self):
        _, _, _, n, p, *_ = build_system()
        n.submit(make_proposal(p, "note", BASE_CTX, {"nested": {"x": 1}}))
        n.read_state()["nested"]["x"] = 2
        self.assertEqual(n.read_state()["nested"]["x"], 1)

    def test_proposal_replay_rejected_before_and_after_restart(self):
        _, k, ledger, n, p, neutron, _ = build_system()
        proposal = make_proposal(p, "note", BASE_CTX, {"x": 1})
        n.submit(proposal)
        for current in (n, Nucleus(k, AtomicLedger(ledger.path), neutron, p.public_key())):
            with self.assertRaises(HandshakeError):
                current.submit(proposal)
        self.assertEqual(len(ledger.entries()), 1)

    def test_restart_authenticates_settlements(self):
        _, k, ledger, _, p, neutron, _ = build_system()
        proposal = make_proposal(p, "note", BASE_CTX, {"hacked": 1})
        ledger.settle({"type": "Settlement", "proposal": proposal,
                      "authorization": {}, "neutron_signature": "00"})
        with self.assertRaises(HandshakeError):
            Nucleus(k, AtomicLedger(ledger.path), neutron, p.public_key())

    def test_two_nuclei_observe_sticky_degraded_state(self):
        _, k, ledger, a, p, neutron, _ = build_system()
        b = Nucleus(k, AtomicLedger(ledger.path), neutron, p.public_key())
        a.submit(make_proposal(p, "mutate_kernel", BASE_CTX, {}))
        with self.assertRaises(DegradedMode):
            b.submit(make_proposal(p, "note", BASE_CTX, {"x": 1}))

    def test_two_ledger_handles_preserve_chain(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d)/"ledger")
            a,b = AtomicLedger(path),AtomicLedger(path)
            a.settle({"a": 1})
            b.settle({"b": 2})
            self.assertTrue(AtomicLedger(path).verify())

    def test_ledger_sequence_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"ledger"
            AtomicLedger(str(path)).settle({"a": 1})
            rec = json.loads(path.read_text())
            rec["seq"] = 999
            path.write_text(json.dumps(rec)+"\n")
            with self.assertRaises(LedgerIntegrityError):
                AtomicLedger(str(path))

    def test_unterminated_complete_ledger_row_is_recoverable(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"ledger"
            AtomicLedger(str(path)).settle({"a": 1})
            path.write_bytes(path.read_bytes().rstrip(b"\r\n"))
            AtomicLedger(str(path)).settle({"b": 2})
            self.assertEqual(len(AtomicLedger(str(path)).entries()), 2)

    def test_empty_and_duplicate_axioms_rejected(self):
        sk = Ed25519PrivateKey.generate()
        for axioms in ([], [AXIOMS[0],AXIOMS[0]]):
            with self.subTest(axioms=axioms), self.assertRaises(KernelError):
                compile_bundle(axioms,sk,"1")

    def test_unknown_predicate_keys_rejected(self):
        ax = copy.deepcopy(AXIOMS[0])
        ax["predicate"]["ignored_security_clause"] = True
        with self.assertRaises(KernelError):
            compile_bundle([ax],Ed25519PrivateKey.generate(),"1")

    def test_signed_invalid_bundle_is_rejected_at_load(self):
        sk = Ed25519PrivateKey.generate()
        body = {"schema":"r08/kernel-bundle/v1","version":"1","axioms":[]}
        bundle = {"body":body,"bundle_digest":digest(body),
                  "steward_signature":sk.sign(canonical_bytes(body)).hex()}
        with self.assertRaises(KernelError):
            ConstitutionalKernel(bundle,sk.public_key())

    def test_quoted_operators_are_data(self):
        for value in ("a and b", "a or b", "a == b", "a != b"):
            with self.subTest(value=value):
                self.assertTrue(evaluate_condition("{{value}} == "+repr(value),{"value":value}))

    def test_invalid_short_circuit_tail_is_rejected(self):
        for expression in ("true or malformed", "false and malformed", "true or 'a' == 'a' garbage"):
            with self.subTest(expression=expression), self.assertRaises(ExpressionError):
                evaluate_condition(expression,{})

    def test_nonfinite_and_out_of_range_threshold_rejected(self):
        report={"results":[]}
        for tau in (float("nan"),float("inf"),-1,2,True):
            with self.subTest(tau=tau), self.assertRaises(ValueError):
                coherence_verdict(report,tau)

    def test_malformed_settlement_verifier_returns_false(self):
        p,n=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
        for record in (None, [], {"proposal":None}):
            with self.subTest(record=record):
                self.assertFalse(verify_settlement_record(record,p.public_key(),n.public_key()))

    def test_failed_ledger_append_does_not_apply_state(self):
        from unittest.mock import patch
        _,_,ledger,n,p,*_=build_system()
        with patch("r08.ledger.os.fsync",side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                n.submit(make_proposal(p,"note",BASE_CTX,{"x":1}))
        self.assertEqual(n.read_state(),{})
        self.assertEqual(ledger.entries(),[])

    def test_same_identity_cannot_act_as_both_parties(self):
        _,k,ledger,_,p,*_=build_system()
        with self.assertRaises(HandshakeError):
            Nucleus(k,ledger,p,p.public_key())

    def test_concurrent_instances_reject_duplicate_settlement(self):
        from concurrent.futures import ThreadPoolExecutor
        _,k,ledger,a,p,neutron,_=build_system()
        b=Nucleus(k,AtomicLedger(ledger.path),neutron,p.public_key())
        proposal=make_proposal(p,"note",BASE_CTX,{"x":1})
        def submit(n):
            try:
                return n.submit(proposal)["decision"]
            except HandshakeError:
                return "replayed"
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(submit,(a,b)))
        self.assertCountEqual(results,["SETTLED","replayed"])
        self.assertEqual(len(ledger.entries()),1)

    def test_empty_ledger_verifies(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(AtomicLedger(str(Path(d)/"ledger")).verify())

    def test_condition_rejects_nonfinite_and_structured_values(self):
        for value in (float("nan"),{},[],None):
            with self.subTest(value=value),self.assertRaises(ExpressionError):
                evaluate_condition("{{x}} == 'allowed'",{"x":value})
