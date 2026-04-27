"""
Unified threat classification pipeline.
Combines rule engine + anomaly detection + MITRE enrichment + cross-layer correlation.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional
import structlog

from .rule_engine import get_rule_engine, RuleMatch
from .anomaly_detector import get_detector
from .mitre_mapper import get_mitre_mapper
from .correlation_engine import get_correlation_engine

logger = structlog.get_logger(__name__)

# Mixing weights
_RULE_WEIGHT = 0.7
_ANOMALY_WEIGHT = 0.3
_CROSS_LAYER_BOOST = 0.15

# Severity thresholds (applied AFTER threat-type override)
_SEVERITY_THRESHOLDS = [
    ("CRITICAL", 0.88),
    ("HIGH",     0.65),
    ("MEDIUM",   0.40),
    ("LOW",      0.0),
]


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class ThreatClassificationResult:
    event_id: str
    threat_type: str           # brute_force | c2_beacon | lateral_movement | data_exfiltration | benign | false_positive
    severity: str              # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float          # 0.0–1.0
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    rule_matches: list[str] = field(default_factory=list)   # fired rule IDs
    anomaly_score: float = 0.0
    explanation: str = ""
    is_false_positive: bool = False
    false_positive_reason: Optional[str] = None
    recommended_action: str = ""
    cross_layer_correlated: bool = False
    correlated_event_ids: list[str] = field(default_factory=list)
    processing_time_ms: float = 0.0

    # Backward-compat properties for old API consumers
    @property
    def is_threat(self) -> bool:
        return self.threat_type not in ("benign", "false_positive")

    @property
    def is_anomaly(self) -> bool:
        return self.anomaly_score >= 0.5

    @property
    def mitre_technique(self) -> Optional[str]:
        return self.mitre_techniques[0].split(" - ")[0] if self.mitre_techniques else None

    @property
    def mitre_tactic(self) -> Optional[str]:
        return self.mitre_tactics[0].split(" - ", 1)[-1] if self.mitre_tactics else None

    @property
    def matched_rules(self):
        """Backward-compat — returns list of rule-ID strings."""
        return self.rule_matches

    @property
    def category(self) -> str:
        return self.threat_type

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "rule_matches": self.rule_matches,
            "anomaly_score": self.anomaly_score,
            "explanation": self.explanation,
            "is_false_positive": self.is_false_positive,
            "false_positive_reason": self.false_positive_reason,
            "recommended_action": self.recommended_action,
            "cross_layer_correlated": self.cross_layer_correlated,
            "correlated_event_ids": self.correlated_event_ids,
            "processing_time_ms": self.processing_time_ms,
            # Legacy fields
            "is_threat": self.is_threat,
            "is_anomaly": self.is_anomaly,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
        }


# ── Explanation templates ─────────────────────────────────────────────────────

def _build_explanation(threat_type: str, event: dict) -> str:
    source_ip = event.get("source_ip") or "unknown"
    dest_ip = event.get("dest_ip") or "unknown"
    bytes_sent = int(event.get("bytes_sent") or 0)
    raw = event.get("raw_payload") or {}

    if threat_type == "brute_force":
        count = raw.get("attempt_number") or len([
            f for f in (event.get("flags") or []) if "brute_force" in f
        ]) or "multiple"
        return (
            f"Repeated authentication failures from {source_ip} ({count} attempts) "
            f"followed by successful login — consistent with credential stuffing attack."
        )
    if threat_type == "c2_beacon":
        interval = raw.get("jitter_seconds") or raw.get("beacon_interval_variance") or 50
        return (
            f"Periodic outbound connections from {source_ip} to {dest_ip} at "
            f"{interval}s intervals with jitter — matches C2 beaconing pattern."
        )
    if threat_type == "lateral_movement":
        return (
            f"Internal host {source_ip} accessing multiple endpoints via SMB/WMI "
            f"— consistent with post-compromise lateral movement."
        )
    if threat_type == "data_exfiltration":
        mb = round(bytes_sent / (1024 * 1024), 1)
        return (
            f"Unusually large outbound transfer ({mb}MB) from {source_ip} "
            f"to external destination."
        )
    if threat_type == "false_positive":
        return (
            f"Traffic matches known backup schedule from admin workstation {source_ip} "
            f"to internal NAS — flagged as false positive."
        )
    return "Normal network activity within baseline parameters."


# ── Recommended action map ────────────────────────────────────────────────────

_ACTIONS = {
    "brute_force":       "Block source IP, enforce MFA, review auth logs for compromised accounts.",
    "c2_beacon":         "Isolate affected host, block C2 destination, initiate IR playbook.",
    "lateral_movement":  "Isolate pivot host, revoke credentials, escalate to CRITICAL incident.",
    "data_exfiltration": "Block egress path, preserve forensic image, notify DLP team.",
    "false_positive":    "No action required — confirmed as scheduled backup activity.",
    "benign":            "Continue monitoring.",
}


# ── Threat type inference ─────────────────────────────────────────────────────

_THREAT_PRIORITY = [
    "false_positive",
    "lateral_movement",
    "data_exfiltration",
    "c2_beacon",
    "brute_force",
    "benign",
]


def _infer_threat_type(matches: list[RuleMatch], event: dict) -> str:
    """Derive threat type from rule matches and event flags (highest priority wins)."""
    flags = event.get("flags") or []

    # Collect threat types from fired rules (exclude false_positive suppressor TV-012
    # since that's handled separately)
    rule_threat_types = {m.threat_type for m in matches if m.rule_id != "TV-012"}

    # Supplement from flags
    flag_threat_types: set[str] = set()
    if any(f in flags for f in ("brute_force_pattern", "credential_stuffing", "tor_exit_node")):
        flag_threat_types.add("brute_force")
    if any(f in flags for f in ("c2_beacon", "periodic_connection", "self_signed_cert")):
        flag_threat_types.add("c2_beacon")
    if any(f in flags for f in ("lateral_movement", "smb_traversal", "credential_dumping")):
        flag_threat_types.add("lateral_movement")

    combined = rule_threat_types | flag_threat_types

    for threat in _THREAT_PRIORITY:
        if threat in combined:
            return threat
    return "benign"


def _severity_from_confidence(confidence: float) -> str:
    for sev, threshold in _SEVERITY_THRESHOLDS:
        if confidence >= threshold:
            return sev
    return "LOW"


# ── Main classifier ───────────────────────────────────────────────────────────

class ThreatClassifier:
    def __init__(self) -> None:
        self.rule_engine = get_rule_engine()
        self.anomaly_detector = get_detector()
        self.mitre_mapper = get_mitre_mapper()
        self.correlation_engine = get_correlation_engine()

    def classify(self, event: dict) -> ThreatClassificationResult:
        t0 = time.perf_counter()

        event_id = event.get("event_id") or ""
        flags = event.get("flags") or []
        generator_confidence = float(event.get("confidence") or 0.0)

        # ── Step 1: Fast-path false positive detection ─────────────────────────
        fp_early = (
            "known_asset" in flags
            and "internal_destination" in flags
            and "business_hours" in flags
        ) or generator_confidence < 0.2

        # ── Step 2: Rule engine ───────────────────────────────────────────────
        matches = self.rule_engine.evaluate(event)
        rule_ids = [m.rule_id for m in matches]
        rule_score = self.rule_engine.get_combined_score(matches)

        # TV-012 is a suppressor — if it fires, it overrides to false_positive
        tv012_fired = any(m.rule_id == "TV-012" for m in matches)

        # ── Step 3: Anomaly detector ──────────────────────────────────────────
        anomaly_score = self.anomaly_detector.score(event)

        # ── Step 4: Combine confidence ────────────────────────────────────────
        final_confidence = (_RULE_WEIGHT * rule_score) + (_ANOMALY_WEIGHT * anomaly_score)
        # Floor: when a high-confidence rule fires, ensure confidence reflects it
        if rule_score >= 0.85:
            final_confidence = max(final_confidence, rule_score * 0.90)
        final_confidence = round(min(final_confidence, 1.0), 4)

        # ── Step 5: Cross-layer correlation ───────────────────────────────────
        self.correlation_engine.add_event(event)
        is_correlated, correlated_ids = self.correlation_engine.check_correlation(event)
        if is_correlated:
            final_confidence = round(min(final_confidence + _CROSS_LAYER_BOOST, 1.0), 4)

        # ── Step 6: Determine threat type ─────────────────────────────────────
        if fp_early or tv012_fired:
            threat_type = "false_positive"
        else:
            threat_type = _infer_threat_type(matches, event)

        # ── Step 7: Severity ──────────────────────────────────────────────────
        if threat_type == "false_positive":
            severity = "LOW"
            final_confidence = 0.05
        elif threat_type == "lateral_movement":
            # Lateral movement is always at least HIGH; CRITICAL when confidence ≥ 0.85
            severity = "CRITICAL" if final_confidence >= 0.85 else "HIGH"
        else:
            severity = self.rule_engine.get_highest_severity(matches)
            # Fall back to confidence-based if no rules fired
            if not matches:
                severity = _severity_from_confidence(final_confidence)

        # ── Step 8: MITRE enrichment ──────────────────────────────────────────
        mitre_tactics = self.mitre_mapper.get_tactics(threat_type)
        mitre_techniques = self.mitre_mapper.get_techniques(threat_type)

        # ── Step 9: Explanation & action ──────────────────────────────────────
        explanation = _build_explanation(threat_type, event)
        recommended_action = _ACTIONS.get(threat_type, _ACTIONS["benign"])

        # FP details
        is_fp = threat_type == "false_positive"
        fp_reason: Optional[str] = None
        if is_fp and tv012_fired:
            fp_reason = "TV-012 suppressor matched: known asset + internal destination + business hours."
        elif is_fp and fp_early and generator_confidence < 0.2:
            fp_reason = f"Generator confidence {generator_confidence:.2f} below threshold (0.20)."
        elif is_fp:
            fp_reason = "Known asset transferring to internal destination during business hours."

        elapsed = (time.perf_counter() - t0) * 1000

        result = ThreatClassificationResult(
            event_id=event_id,
            threat_type=threat_type,
            severity=severity,
            confidence=final_confidence,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            rule_matches=rule_ids,
            anomaly_score=round(anomaly_score, 4),
            explanation=explanation,
            is_false_positive=is_fp,
            false_positive_reason=fp_reason,
            recommended_action=recommended_action,
            cross_layer_correlated=is_correlated,
            correlated_event_ids=correlated_ids,
            processing_time_ms=round(elapsed, 2),
        )

        logger.debug(
            "event_classified",
            event_id=event_id,
            threat_type=threat_type,
            severity=severity,
            confidence=final_confidence,
            rules=rule_ids,
            anomaly=round(anomaly_score, 3),
            correlated=is_correlated,
            processing_ms=round(elapsed, 2),
        )

        # ── Audit: log threats and false positives (skip benign to reduce volume)
        if threat_type != "benign":
            _schedule_classification_audit(result, event)

        return result


def _schedule_classification_audit(
    result: "ThreatClassificationResult",
    event: dict,
) -> None:
    """
    Fire-and-forget audit log for threat classification.
    Runs as a background asyncio task — never blocks the classifier.
    """
    import asyncio
    from app.services.audit_service import log_event
    try:
        asyncio.get_running_loop().create_task(log_event(
            actor_type="system",
            actor_id="threat_classifier",
            action="threat_classified",
            target_type="event",
            target_id=result.event_id or "unknown",
            result="success" if not result.is_false_positive else "success",
            confidence=result.confidence,
            duration_ms=int(result.processing_time_ms),
            metadata={
                "threat_type": result.threat_type,
                "severity": result.severity,
                "confidence": result.confidence,
                "rule_matches": result.rule_matches,
                "anomaly_score": result.anomaly_score,
                "is_false_positive": result.is_false_positive,
                "cross_layer_correlated": result.cross_layer_correlated,
                "bytes_sent": int(event.get("bytes_sent") or 0),
                "source_ip": event.get("source_ip"),
                "dest_ip": event.get("dest_ip"),
                "mitre_techniques": result.mitre_techniques[:3],
            },
        ))
    except RuntimeError:
        pass  # No running event loop — skip audit in test/seed context


# ── Module-level singleton + legacy function ──────────────────────────────────

_classifier: Optional[ThreatClassifier] = None


def get_classifier() -> ThreatClassifier:
    global _classifier
    if _classifier is None:
        _classifier = ThreatClassifier()
    return _classifier


def classify_event(event: dict) -> ThreatClassificationResult:
    """Module-level convenience function (backward-compatible entry point)."""
    return get_classifier().classify(event)
