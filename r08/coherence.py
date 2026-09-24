"""Real-time coherence scoring (C_coherence in [0.0, 1.0]) — provisional
metric specification v0.1 (AF-14: the normative metric spec, calibration
corpus, and ratified tau_coherence remain DECISION REQUIRED; this
deterministic, versioned scorer is explicitly provisional).

Score model: start at 1.0; each violated axiom subtracts a severity
weight (critical 1.0 — immediate collapse, high 0.5, medium 0.25); each
evaluation error on an axiom subtracts its full weight (fail closed on
uncertainty). The score is clamped to [0.0, 1.0]. Threshold transitions
are deterministic: same inputs, same score, same transition.
"""

from __future__ import annotations

import math

METRIC_VERSION = "0.1-provisional"
SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.5, "medium": 0.25}
DEFAULT_TAU_COHERENCE = 0.75      # provisional; ratification DECISION REQUIRED


def coherence_score(kernel_report: dict) -> float:
    score = 1.0
    for r in kernel_report["results"]:
        if r["status"] != "satisfied":
            score -= SEVERITY_WEIGHT[r["severity"]]
    return max(0.0, min(1.0, score))


def coherence_verdict(kernel_report: dict,
                      tau: float = DEFAULT_TAU_COHERENCE) -> dict:
    if type(tau) not in (int, float) or not math.isfinite(tau) or not 0 <= tau <= 1:
        raise ValueError("coherence threshold must be finite and within [0, 1]")
    c = coherence_score(kernel_report)
    return {"metric_version": METRIC_VERSION, "C_coherence": c,
            "tau_coherence": tau, "collapse": c < tau}
