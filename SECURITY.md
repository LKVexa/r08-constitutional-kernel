# Security boundary

Only trusted stewards may supply policy bundles and trusted services may hold
the proton/neutron keys. These are API role separations within a Python process;
they do not isolate a hostile process participant or provide hardware anchoring.
Never treat mutable Python attributes as a hardware security boundary.

Ledger directories require OS protection. Local file locks coordinate cooperating
instances; they do not authenticate the filesystem or support distributed
consensus. An independent authenticated checkpoint is required to detect a
complete rewrite or deletion of a valid trailing sequence.

Settlement replay checks require the configured proton/neutron keys and kernel
digest. Key rotation and policy migrations are not implemented. Historical
unsigned degraded records remain fail-closed. A disk error can prevent a
degraded transition from being persisted; the current instance latches the
fault and refuses further submissions, but a durable external fault mechanism
is still required before automated restarts in a production design.

The coherence metric is provisional. Governance decisions, hardware trust
anchoring, recovery, certification, distributed quorum, network-filesystem
behavior and large-ledger performance remain open. Full-ledger validation on
each transaction favors correctness over throughput.

Report vulnerabilities through private repository advisories when available.
