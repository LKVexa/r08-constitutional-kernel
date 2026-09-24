"""Signed policy evaluation with replay-safe, serialized local settlement."""
from __future__ import annotations
import copy
import json
import math
import threading
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .kernel import ConstitutionalKernel, canonical_bytes, digest
from .coherence import DEFAULT_TAU_COHERENCE, coherence_verdict
from .ledger import AtomicLedger, LedgerIntegrityError

MODE_NOMINAL="NOMINAL"
MODE_DEGRADED="DEGRADED"


class HandshakeError(Exception):
    pass


class DegradedMode(Exception):
    pass


def _key_bytes(key):
    return key.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)


def _validate_proposal(proposal,proton_pub):
    if not isinstance(proposal,dict) or set(proposal)!={"body","proposal_digest","proton_signature"}:
        raise HandshakeError("invalid proposal envelope")
    body=proposal["body"]
    if not isinstance(body,dict) or set(body)!={"schema","proposal_id","intent","context","payload","created_at"}:
        raise HandshakeError("invalid proposal body")
    if body["schema"]!="r08/proposal-envelope/v1":
        raise HandshakeError("unknown proposal schema")
    if not all(isinstance(body[k],str) and body[k].strip() for k in ("proposal_id","intent")):
        raise HandshakeError("proposal ID and intent must be non-empty strings")
    if not isinstance(body["context"],dict) or not isinstance(body["payload"],dict):
        raise HandshakeError("context and payload must be objects")
    if type(body["created_at"]) not in (int,float) or not math.isfinite(body["created_at"]):
        raise HandshakeError("invalid proposal timestamp")
    try:
        payload=canonical_bytes(body)
        if digest(payload)!=proposal["proposal_digest"]:
            raise HandshakeError("proposal digest mismatch")
        proton_pub.verify(bytes.fromhex(proposal["proton_signature"]),payload)
    except (InvalidSignature,KeyError,ValueError,TypeError,RecursionError) as exc:
        raise HandshakeError("invalid proposal signature or content") from exc
    return body


def make_proposal(proton_key: Ed25519PrivateKey,intent:str,context:dict,payload:dict)->dict:
    body=json.loads(canonical_bytes({"schema":"r08/proposal-envelope/v1",
         "proposal_id":str(uuid.uuid4()),"intent":intent,"context":context,
         "payload":payload,"created_at":time.time()}))
    envelope={"body":body,"proposal_digest":digest(body),
              "proton_signature":proton_key.sign(canonical_bytes(body)).hex()}
    _validate_proposal(envelope,proton_key.public_key())
    return envelope


def verify_settlement_record(settlement,proton_pub,neutron_pub,*,kernel_digest=None):
    """Verify signatures and bindings; keys and expected kernel come from the caller."""
    try:
        if _key_bytes(proton_pub)==_key_bytes(neutron_pub):
            return False
        if not isinstance(settlement,dict) or set(settlement)!={"type","proposal","authorization","neutron_signature"}:
            return False
        if settlement["type"]!="Settlement":
            return False
        prop=settlement["proposal"]
        _validate_proposal(prop,proton_pub)
        auth=settlement["authorization"]
        if not isinstance(auth,dict) or set(auth)!={"schema","proposal_digest","kernel_bundle_digest","coherence","authorized_at"}:
            return False
        if auth["schema"]!="r08/neutron-authorization/v1" or auth["proposal_digest"]!=prop["proposal_digest"]:
            return False
        if kernel_digest is not None and auth["kernel_bundle_digest"]!=kernel_digest:
            return False
        neutron_pub.verify(bytes.fromhex(settlement["neutron_signature"]),canonical_bytes(auth))
        return True
    except (HandshakeError,InvalidSignature,KeyError,ValueError,TypeError,AttributeError,RecursionError):
        return False


class Nucleus:
    def __init__(self,kernel:ConstitutionalKernel,ledger:AtomicLedger,
                 neutron_key:Ed25519PrivateKey,proton_pub:Ed25519PublicKey,
                 tau:float=DEFAULT_TAU_COHERENCE):
        if _key_bytes(neutron_key.public_key())==_key_bytes(proton_pub):
            raise HandshakeError("proton and neutron must use distinct identities")
        coherence_verdict({"results":[]},tau)
        self.kernel,self.ledger=kernel,ledger
        self._neutron_key,self._proton_pub=neutron_key,proton_pub
        self.tau=tau
        self._lock=threading.RLock()
        self.mode,self._state,self._seen=MODE_NOMINAL,{},set()
        self._faulted=False
        with self.ledger.transaction():
            self._restore()

    def _restore(self):
        state,seen,mode={},set(),MODE_NOMINAL
        for entry in self.ledger.entries():
            if entry.get("type")=="Settlement":
                if mode==MODE_DEGRADED or not verify_settlement_record(
                    entry,self._proton_pub,self._neutron_key.public_key(),
                    kernel_digest=self.kernel.bundle_digest):
                    raise HandshakeError("ledger contains an unauthorized settlement")
                body=entry["proposal"]["body"]
                if body["proposal_id"] in seen:
                    raise HandshakeError("ledger replays a proposal ID")
                seen.add(body["proposal_id"])
                state.update(copy.deepcopy(body["payload"]))
            elif entry.get("type")=="DegradedTransition":
                # Historical unsigned degraded records still fail closed.
                mode=MODE_DEGRADED
            else:
                raise HandshakeError("unknown nucleus ledger record")
        self._state,self._seen=state,seen
        self.mode=MODE_DEGRADED if self._faulted else mode

    def read_state(self):
        with self._lock,self.ledger.transaction():
            self._restore()
            return copy.deepcopy(self._state)

    def submit(self,proposal):
        # Freeze caller-owned nested data before verification.
        try:
            proposal=json.loads(canonical_bytes(proposal))
        except (TypeError,ValueError,RecursionError) as exc:
            raise HandshakeError("invalid proposal JSON data") from exc
        with self._lock,self.ledger.transaction():
            self._restore()
            if self.mode==MODE_DEGRADED:
                raise DegradedMode("fail-closed: nucleus is read-only")
            body=_validate_proposal(proposal,self._proton_pub)
            if body["proposal_id"] in self._seen:
                raise HandshakeError("proposal ID already settled")
            context=dict(body["context"],intent=body["intent"])
            report=self.kernel.evaluate(context)
            coh=coherence_verdict(report,self.tau)
            if report["verdict"]!="PASS" or coh["collapse"]:
                transition={"type":"DegradedTransition","proposal_digest":proposal["proposal_digest"],
                            "kernel_report":report,"coherence":coh,"mode":MODE_DEGRADED,"at":time.time()}
                try:
                    self.ledger.settle(transition)
                except OSError:
                    self._faulted=True
                    self.mode=MODE_DEGRADED
                    raise
                self.mode=MODE_DEGRADED
                return {"decision":"REFUSED_FAIL_CLOSED","kernel_report":report,
                        "coherence":coh,"mode":self.mode}
            authorization={"schema":"r08/neutron-authorization/v1",
                           "proposal_digest":proposal["proposal_digest"],
                           "kernel_bundle_digest":report["bundle_digest"],
                           "coherence":coh,"authorized_at":time.time()}
            settlement={"type":"Settlement","proposal":proposal,"authorization":authorization,
                        "neutron_signature":self._neutron_key.sign(canonical_bytes(authorization)).hex()}
            if not verify_settlement_record(settlement,self._proton_pub,self._neutron_key.public_key(),
                                             kernel_digest=self.kernel.bundle_digest):
                raise HandshakeError("settlement preparation failed")
            rec=self.ledger.settle(settlement)
            self._state.update(copy.deepcopy(body["payload"]))
            self._seen.add(body["proposal_id"])
            return {"decision":"SETTLED","seq":rec["seq"],"merkle_root":rec["merkle_root"],
                    "coherence":coh,"mode":self.mode}
