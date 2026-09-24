import copy
from pathlib import Path
import json
import os
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from r08.kernel import (ConstitutionalKernel, KernelError, SealViolation,
                        compile_bundle, digest)
from r08.coherence import coherence_score, coherence_verdict
from r08.nucleus import (AtomicLedger, DegradedMode, HandshakeError,
                         MODE_DEGRADED, MODE_NOMINAL, Nucleus, make_proposal,
                         verify_settlement_record)

AXIOMS = [
    {"axiom_id": "K-01", "title": "No kernel mutation intents", "severity": "critical",
     "predicate": {"not": {"condition": "{{intent}} == 'mutate_kernel'"}}},
    {"axiom_id": "K-02", "title": "Human prerequisite for external tools", "severity": "critical",
     "predicate": {"any": [
         {"not": {"condition": "{{uses_external_tool}} == 'true'"}},
         {"condition": "{{human_approval}} == 'granted'"}]}},
    {"axiom_id": "K-03", "title": "Scratchpad writes stay in scratchpad", "severity": "high",
     "predicate": {"any": [
         {"not": {"condition": "{{target}} == 'persistent_memory'"}},
         {"condition": "{{countersign_requested}} == 'true'"}]}},
    {"axiom_id": "K-04", "title": "Declared provenance", "severity": "medium",
     "predicate": {"condition": "{{provenance}} == 'declared'"}},
]

BASE_CTX = {"uses_external_tool": "false", "target": "scratchpad",
            "provenance": "declared", "human_approval": "none",
            "countersign_requested": "false"}


def build_system(tau=0.75):
    steward = Ed25519PrivateKey.generate()
    proton = Ed25519PrivateKey.generate()
    neutron = Ed25519PrivateKey.generate()
    sealed = compile_bundle(AXIOMS, steward, "1.0.0")
    kernel = ConstitutionalKernel(sealed, steward.public_key())
    ledger = AtomicLedger(os.path.join(tempfile.mkdtemp(), "ledger.jsonl"))
    nucleus = Nucleus(kernel, ledger, neutron, proton.public_key(), tau)
    return sealed, kernel, ledger, nucleus, proton, neutron, steward


class KernelSeal(unittest.TestCase):
    def test_load_and_evaluate(self):
        _, kernel, *_ = build_system()
        rep = kernel.evaluate(dict(BASE_CTX, intent="write_note"))
        self.assertEqual(rep["verdict"], "PASS")

    def test_tampered_bundle_refused(self):
        sealed, *_ , steward = build_system()
        evil = copy.deepcopy(sealed)
        evil["body"]["axioms"][0]["predicate"] = {"condition": "true == true"}
        with self.assertRaises(SealViolation):
            ConstitutionalKernel(evil, steward.public_key())

    def test_wrong_steward_key_refused(self):
        sealed, *_ = build_system()
        with self.assertRaises(SealViolation):
            ConstitutionalKernel(sealed, Ed25519PrivateKey.generate().public_key())

    def test_in_memory_mutation_detected(self):
        _, kernel, *_ = build_system()
        kernel._body["axioms"][0]["predicate"] = {"condition": "'a' == 'a'"}
        with self.assertRaises(SealViolation):
            kernel.evaluate(dict(BASE_CTX, intent="x"))

    def test_evaluation_error_fails_closed(self):
        steward = Ed25519PrivateKey.generate()
        sealed = compile_bundle(
            [{"axiom_id": "K-E", "title": "refs undefined var", "severity": "critical",
              "predicate": {"condition": "{{no_such_field}} == 'x'"}}],
            steward, "1.0.0")
        kernel = ConstitutionalKernel(sealed, steward.public_key())
        rep = kernel.evaluate({"intent": "x"})
        self.assertEqual(rep["verdict"], "VIOLATION")

    def test_invalid_tree_rejected_at_compile(self):
        with self.assertRaises(KernelError):
            compile_bundle([{"axiom_id": "B", "title": "t", "severity": "high",
                             "predicate": {"all": []}}],
                           Ed25519PrivateKey.generate(), "1")


class Coherence(unittest.TestCase):
    def report(self, statuses):
        return {"results": [{"severity": s, "status": st}
                            for s, st in statuses],
                "bundle_digest": "sha256:x", "kernel_version": "1"}

    def test_score_bounds_and_weights(self):
        self.assertEqual(coherence_score(self.report([("critical", "satisfied")])), 1.0)
        self.assertEqual(coherence_score(self.report([("critical", "violated")])), 0.0)
        self.assertEqual(coherence_score(self.report([("high", "violated")])), 0.5)
        self.assertEqual(coherence_score(self.report([("medium", "violated")])), 0.75)

    def test_deterministic_threshold_transition(self):
        r = self.report([("high", "violated")])
        for _ in range(3):
            v = coherence_verdict(r, tau=0.75)
            self.assertEqual(v["C_coherence"], 0.5)
            self.assertTrue(v["collapse"])
        self.assertFalse(coherence_verdict(r, tau=0.5)["collapse"])


class Handshake(unittest.TestCase):
    def test_golden_settlement_dual_signed(self):
        _, _, ledger, nucleus, proton, neutron, _ = build_system()
        p = make_proposal(proton, "write_note", BASE_CTX, {"note": "hello"})
        res = nucleus.submit(p)
        self.assertEqual(res["decision"], "SETTLED")
        self.assertEqual(nucleus.read_state()["note"], "hello")
        self.assertTrue(ledger.verify())
        entry = ledger.entries()[-1]
        self.assertTrue(verify_settlement_record(
            entry, proton.public_key(), neutron.public_key()))

    def test_proton_has_no_direct_authority(self):
        _, _, _, nucleus, *_ = build_system()
        self.assertFalse(hasattr(nucleus, "write_state"))
        # read_state returns a copy; mutating it changes nothing
        s = nucleus.read_state()
        s["hacked"] = True
        self.assertNotIn("hacked", nucleus.read_state())

    def test_forged_proton_signature_rejected(self):
        _, _, _, nucleus, _, _, _ = build_system()
        outsider = Ed25519PrivateKey.generate()
        p = make_proposal(outsider, "write_note", BASE_CTX, {"note": "x"})
        with self.assertRaises(HandshakeError):
            nucleus.submit(p)

    def test_tampered_payload_rejected(self):
        _, _, _, nucleus, proton, *_ = build_system()
        p = make_proposal(proton, "write_note", BASE_CTX, {"note": "x"})
        p["body"]["payload"]["note"] = "evil"
        with self.assertRaises(HandshakeError):
            nucleus.submit(p)

    def test_settlement_record_forgery_detected(self):
        _, _, ledger, nucleus, proton, neutron, _ = build_system()
        nucleus.submit(make_proposal(proton, "write_note", BASE_CTX, {"a": 1}))
        entry = copy.deepcopy(ledger.entries()[-1])
        entry["proposal"]["body"]["payload"]["a"] = 999
        self.assertFalse(verify_settlement_record(
            entry, proton.public_key(), neutron.public_key()))


class FailClosed(unittest.TestCase):
    def test_kernel_mutation_intent_triggers_degraded(self):
        _, _, ledger, nucleus, proton, *_ = build_system()
        p = make_proposal(proton, "mutate_kernel", BASE_CTX, {})
        res = nucleus.submit(p)
        self.assertEqual(res["decision"], "REFUSED_FAIL_CLOSED")
        self.assertEqual(nucleus.mode, MODE_DEGRADED)
        self.assertEqual(ledger.entries()[-1]["type"], "DegradedTransition")

    def test_degraded_mode_is_read_only_and_sticky(self):
        _, _, _, nucleus, proton, *_ = build_system()
        nucleus.submit(make_proposal(proton, "mutate_kernel", BASE_CTX, {}))
        with self.assertRaises(DegradedMode):
            nucleus.submit(make_proposal(proton, "write_note", BASE_CTX, {"n": 1}))
        nucleus.read_state()                      # reads still allowed
        self.assertEqual(nucleus.mode, MODE_DEGRADED)

    def test_coherence_collapse_triggers_degraded(self):
        # medium violation only -> C=0.75; with tau=0.8 that collapses
        _, _, _, nucleus, proton, *_ = build_system(tau=0.8)
        ctx = dict(BASE_CTX, provenance="undeclared")
        res = nucleus.submit(make_proposal(proton, "write_note", ctx, {"n": 1}))
        self.assertEqual(res["decision"], "REFUSED_FAIL_CLOSED")
        self.assertTrue(res["coherence"]["collapse"])

    def test_state_unchanged_after_refusal(self):
        _, _, _, nucleus, proton, *_ = build_system()
        nucleus.submit(make_proposal(proton, "mutate_kernel", BASE_CTX, {"evil": 1}))
        self.assertEqual(nucleus.read_state(), {})


class Ledger(unittest.TestCase):
    def test_tamper_detection(self):
        led = AtomicLedger(os.path.join(tempfile.mkdtemp(), "l.jsonl"))
        led.settle({"type": "Settlement", "n": 1})
        led.settle({"type": "Settlement", "n": 2})
        self.assertTrue(led.verify())
        lines = Path(led.path).read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["entry"]["n"] = 99
        lines[0] = json.dumps(rec, sort_keys=True)
        Path(led.path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        # 0.1.1 strengthens tamper handling: a tampered ledger is refused
        # at load itself (LedgerIntegrityError), not merely reported by
        # verify() on demand.
        from r08.nucleus import LedgerIntegrityError
        with self.assertRaises(LedgerIntegrityError):
            AtomicLedger(led.path)


if __name__ == "__main__":
    unittest.main()


class MaintenanceRepairs011(unittest.TestCase):
    """0.1.1-partial: evaluator injection immunity, ledger recovery and
    load-time verification, restart-sticky fail-closed mode."""

    def _stack(self, path, axioms=None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import \
            Ed25519PrivateKey
        from r08.kernel import compile_bundle, ConstitutionalKernel
        from r08.nucleus import Nucleus, AtomicLedger
        sk = Ed25519PrivateKey.generate()
        prot = Ed25519PrivateKey.generate()
        neut = Ed25519PrivateKey.generate()
        ax = axioms or [{"axiom_id": "AX1", "title": "not root",
                         "severity": "critical",
                         "predicate": {"condition": "{{user}} != 'root'"}}]
        k = ConstitutionalKernel(compile_bundle(ax, sk, "1.0"),
                                 sk.public_key())
        return k, AtomicLedger(path), prot, neut

    def setUp(self):
        import tempfile
        self.t = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.t)

    def test_quote_in_data_evaluates_correctly_not_error(self):
        import os
        from r08.nucleus import Nucleus, make_proposal
        k, led, prot, neut = self._stack(os.path.join(self.t, "l.jsonl"))
        n = Nucleus(k, led, neut, prot.public_key())
        p = make_proposal(prot, "op", {"user": "O'Brien"}, {"a": 1})
        r = n.submit(p)
        self.assertEqual(r["decision"], "SETTLED")   # satisfied, not error

    def test_injection_keywords_in_data_cannot_alter_expression(self):
        import os
        from r08.nucleus import Nucleus, make_proposal
        k, led, prot, neut = self._stack(os.path.join(self.t, "l.jsonl"))
        n = Nucleus(k, led, neut, prot.public_key())
        # value crafted to read as: 'root' != 'root' or true — must simply
        # compare unequal to "root" as DATA and stay satisfied
        p = make_proposal(prot, "op",
                          {"user": "root' != 'root' or true"}, {"a": 1})
        r = n.submit(p)
        self.assertEqual(r["decision"], "SETTLED")
        # and the exact value "root" is still refused
        n2 = Nucleus(k, type(led)(led.path + "2"), neut, prot.public_key())
        r2 = n2.submit(make_proposal(prot, "op", {"user": "root"}, {}))
        self.assertEqual(r2["decision"], "REFUSED_FAIL_CLOSED")

    def test_degraded_mode_survives_restart_and_state_replays(self):
        import os
        from r08.nucleus import (Nucleus, AtomicLedger, make_proposal,
                                 MODE_DEGRADED, DegradedMode)
        path = os.path.join(self.t, "l.jsonl")
        k, led, prot, neut = self._stack(path)
        n = Nucleus(k, led, neut, prot.public_key())
        n.submit(make_proposal(prot, "op", {"user": "alice"}, {"x": 1}))
        n.submit(make_proposal(prot, "op", {"user": "root"}, {}))  # degrade
        self.assertEqual(n.mode, MODE_DEGRADED)
        n2 = Nucleus(k, AtomicLedger(path), neut, prot.public_key())
        self.assertEqual(n2.mode, MODE_DEGRADED)      # sticky across restart
        self.assertEqual(n2.read_state(), {"x": 1})   # state replayed
        with self.assertRaises(DegradedMode):
            n2.submit(make_proposal(prot, "op", {"user": "bob"}, {"y": 2}))

    def test_ledger_crash_tail_recovered(self):
        import os
        from r08.nucleus import AtomicLedger
        path = os.path.join(self.t, "l.jsonl")
        led = AtomicLedger(path)
        led.settle({"a": 1})
        with open(path, "a") as fh:
            fh.write('{"entry":{"ty')          # torn tail
        led2 = AtomicLedger(path)
        self.assertEqual(led2.entries(), [{"a": 1}])
        self.assertTrue(led2.verify())

    def test_ledger_tamper_detected_at_load(self):
        import os, json
        from r08.nucleus import AtomicLedger, LedgerIntegrityError
        path = os.path.join(self.t, "l.jsonl")
        led = AtomicLedger(path)
        led.settle({"a": 1}); led.settle({"b": 2})
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        e = json.loads(lines[0]); e["entry"]["a"] = 999
        lines[0] = json.dumps(e, sort_keys=True, ensure_ascii=False)
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(LedgerIntegrityError):
            AtomicLedger(path)
