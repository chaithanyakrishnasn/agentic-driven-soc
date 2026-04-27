"""
Blue Agent — AI-powered defender that analyzes incidents and generates
dynamic response playbooks using Claude.
Maintains ChromaDB memory of past playbooks and resolutions.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Optional

import structlog
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from app.config import get_settings

logger = structlog.get_logger(__name__)


# ── Result dataclasses ────────────────────────────────────────────────────────

@dataclass
class IncidentAnalysis:
    incident_id: str
    severity: str
    threat_summary: str
    attack_chain: list[str]
    affected_assets: list[str]
    root_cause: str
    business_impact: str
    confidence: float
    recommended_priority: str  # "immediate" | "high" | "medium" | "low"


@dataclass
class PlaybookStep:
    step_id: str
    title: str
    description: str
    commands: list[str]
    expected_outcome: str
    estimated_minutes: int


@dataclass
class PlaybookPhase:
    phase_name: str
    priority: int
    steps: list[PlaybookStep]


@dataclass
class ResponsePlaybook:
    playbook_id: str
    incident_id: str
    threat_type: str
    title: str
    phases: list[PlaybookPhase]
    estimated_time_minutes: int
    required_tools: list[str]
    success_criteria: list[str]


@dataclass
class AlertExplanation:
    what_happened: str
    why_suspicious: str
    false_positive_likelihood: str
    false_positive_reason: str
    recommended_action: str
    confidence_explanation: str


@dataclass
class TriageDecision:
    decision: str      # "escalate" | "monitor" | "close" | "investigate"
    reason: str
    priority: int      # 1-5
    assigned_to: str   # "tier1" | "tier2" | "tier3" | "management"
    sla_minutes: int


# ── Audit helper ─────────────────────────────────────────────────────────────

def _fire_blue_audit(
    action: str,
    incident_id: str,
    reasoning: str,
    confidence: float,
    metadata: dict,
) -> None:
    """Schedule a fire-and-forget audit log entry for BlueAgent decisions."""
    from app.services.audit_service import fire_and_forget, log_event
    fire_and_forget(log_event(
        actor_type="agent",
        actor_id="blue_agent",
        action=action,
        target_type="incident",
        target_id=incident_id,
        result="success",
        reasoning=reasoning,
        confidence=confidence,
        metadata=metadata,
    ))


# ── Fallback builders ─────────────────────────────────────────────────────────

_PHASE_COMMANDS: dict[str, dict[str, list[str]]] = {
    "brute_force": {
        "Containment": [
            "iptables -A INPUT -s {source_ip} -j DROP",
            "netsh advfirewall firewall add rule name='Block {source_ip}' dir=in action=block remoteip={source_ip}",
        ],
        "Eradication": [
            "Get-EventLog -LogName Security -InstanceId 4625 | Where-Object {$_.Message -like '*{source_ip}*'}",
            "usermod -L {username}",
        ],
        "Recovery": ["net user {username} /active:yes", "grep 'Accepted' /var/log/auth.log | tail -20"],
        "Lessons Learned": ["Review MFA enforcement policy", "Implement account lockout threshold"],
    },
    "c2_beacon": {
        "Containment": [
            "iptables -A OUTPUT -d {dest_ip} -j DROP",
            "ss -tulnp | grep {dest_port}",
        ],
        "Eradication": [
            "kill -9 $(lsof -ti:{dest_port})",
            "strings /proc/{pid}/exe | grep -i http",
            "crontab -l && cat /etc/cron*/*",
        ],
        "Recovery": ["ss -tulnp && netstat -antp | grep ESTABLISHED", "Restore host from clean image"],
        "Lessons Learned": ["Deploy network egress filtering", "Implement JA3/JA3S signature detection"],
    },
    "lateral_movement": {
        "Containment": [
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false",
            "net session",
        ],
        "Eradication": [
            "Get-WmiObject Win32_Process | Where-Object {$_.Name -eq 'wmic.exe'}",
            "Get-LocalGroupMember -Group Administrators",
        ],
        "Recovery": [
            "Invoke-Command -ComputerName {host} -ScriptBlock {Get-Process}",
            "Get-EventLog -LogName Security -InstanceId 4624 -Newest 50",
        ],
        "Lessons Learned": ["Implement network segmentation", "Enforce least-privilege for service accounts"],
    },
    "data_exfiltration": {
        "Containment": [
            "iptables -A FORWARD -s {source_ip} -j DROP",
            "tcpdump -i eth0 'dst {dest_ip}' -w /tmp/capture.pcap",
        ],
        "Eradication": [
            "lsof -i TCP | grep ESTABLISHED",
            "find / -name '*.zip' -newer /tmp/sentinel -mtime -1",
        ],
        "Recovery": ["Restore data from backup", "Verify data integrity"],
        "Lessons Learned": ["Deploy DLP solution", "Implement egress filtering rules"],
    },
}


def _fallback_incident_analysis(events: list[dict], classifications: list[dict]) -> IncidentAnalysis:
    threat_types = [c.get("threat_type", "unknown") for c in classifications if c.get("is_threat")]
    primary = threat_types[0] if threat_types else "unknown"
    severities = [c.get("severity", "LOW") for c in classifications]
    max_sev = "CRITICAL" if "CRITICAL" in severities else "HIGH" if "HIGH" in severities else "MEDIUM"
    source_ips = list({e.get("source_ip", "") for e in events if e.get("source_ip")})
    dest_ips = list({e.get("dest_ip", "") for e in events if e.get("dest_ip")})

    return IncidentAnalysis(
        incident_id=str(uuid.uuid4()),
        severity=max_sev,
        threat_summary=(
            f"Security incident involving {primary} activity detected across {len(events)} events. "
            f"Source IPs: {', '.join(source_ips[:3])}. Immediate investigation required."
        ),
        attack_chain=[
            "Initial reconnaissance or access",
            f"Threat activity: {primary}",
            "Potential lateral movement or privilege escalation",
            "Data collection or impact phase",
        ],
        affected_assets=list(set(source_ips[:3] + dest_ips[:3])),
        root_cause=f"Detected {primary} pattern indicating active compromise or attack.",
        business_impact="Potential data breach, service disruption, or credential compromise.",
        confidence=max((c.get("confidence", 0.5) for c in classifications), default=0.5),
        recommended_priority="immediate" if max_sev == "CRITICAL" else "high",
    )


def _fallback_playbook(
    incident: IncidentAnalysis,
    threat_type: str,
    env: dict,
) -> ResponsePlaybook:
    cmds = _PHASE_COMMANDS.get(threat_type, _PHASE_COMMANDS["brute_force"])
    phases = []
    for priority, (phase_name, phase_cmds) in enumerate([
        ("Containment", cmds.get("Containment", [])),
        ("Eradication", cmds.get("Eradication", [])),
        ("Recovery", cmds.get("Recovery", [])),
        ("Lessons Learned", cmds.get("Lessons Learned", [])),
    ], start=1):
        steps = [
            PlaybookStep(
                step_id=f"{phase_name[0]}{i}",
                title=f"{phase_name} Step {i}",
                description=cmd,
                commands=[cmd],
                expected_outcome=f"Execute {phase_name.lower()} action successfully",
                estimated_minutes=5,
            )
            for i, cmd in enumerate(phase_cmds, start=1)
        ]
        phases.append(PlaybookPhase(phase_name=phase_name, priority=priority, steps=steps))

    return ResponsePlaybook(
        playbook_id=str(uuid.uuid4()),
        incident_id=incident.incident_id,
        threat_type=threat_type,
        title=f"IR Playbook: {threat_type.replace('_', ' ').title()} — {incident.severity}",
        phases=phases,
        estimated_time_minutes=60,
        required_tools=["SIEM", "EDR", "Firewall CLI", "Active Directory"],
        success_criteria=[
            "Attacker access blocked at perimeter",
            "Compromised credentials reset",
            "No new C2 connections detected for 24h",
        ],
    )


# ── Blue Agent ────────────────────────────────────────────────────────────────

class BlueAgent:
    """AI-powered defender that analyzes incidents and generates response playbooks."""

    def __init__(self) -> None:
        settings = get_settings()
        self.llm = ChatAnthropic(
            model="claude-opus-4-5",
            api_key=settings.anthropic_api_key,
            max_tokens=3000,
            timeout=30,
            max_retries=0,
        )
        self.fast_llm = ChatAnthropic(
            model="claude-haiku-4-5-20251001",
            api_key=settings.anthropic_api_key,
            max_tokens=600,
            timeout=30,
            max_retries=0,
        )
        self._chroma = self._init_chroma(settings)

    def _init_chroma(self, settings):
        import socket
        # Fast pre-check: is ChromaDB port open? (1-second timeout to avoid hanging)
        try:
            with socket.create_connection((settings.chroma_host, settings.chroma_port), timeout=1):
                pass
        except OSError:
            try:
                import chromadb
                return chromadb.EphemeralClient().get_or_create_collection("blue_agent_playbooks")
            except Exception as exc:
                logger.warning("blue_agent_chroma_unavailable", error=str(exc))
                return None

        try:
            import chromadb
            client = chromadb.HttpClient(host=settings.chroma_host, port=settings.chroma_port)
            client.heartbeat()
            return client.get_or_create_collection("blue_agent_playbooks")
        except Exception:
            try:
                import chromadb
                return chromadb.EphemeralClient().get_or_create_collection("blue_agent_playbooks")
            except Exception as exc:
                logger.warning("blue_agent_chroma_unavailable", error=str(exc))
                return None

    def _store_playbook(self, playbook: ResponsePlaybook) -> None:
        if not self._chroma:
            return
        try:
            self._chroma.upsert(
                ids=[playbook.playbook_id],
                documents=[f"{playbook.threat_type} {playbook.title}"],
                metadatas=[{
                    "threat_type": playbook.threat_type,
                    "incident_id": playbook.incident_id,
                    "phase_count": len(playbook.phases),
                }],
            )
        except Exception as exc:
            logger.warning("blue_agent_playbook_store_error", error=str(exc))

    def _retrieve_similar(self, query: str, n: int = 2) -> list[str]:
        if not self._chroma:
            return []
        try:
            count = self._chroma.count()
            if count == 0:
                return []
            results = self._chroma.query(
                query_texts=[query],
                n_results=min(n, count),
            )
            return results.get("documents", [[]])[0]
        except Exception:
            return []

    # ── explain_alert ─────────────────────────────────────────────────────────

    async def explain_alert(
        self,
        event: dict,
        classification: dict,
    ) -> AlertExplanation:
        """Explain a single alert in plain English for a junior analyst."""
        system_msg = (
            "You are a SOC analyst explaining security alerts to a junior analyst. "
            "Be clear and educational. Always respond in valid JSON."
        )
        user_msg = f"""Explain this security alert:

Event: {json.dumps(event, default=str)[:600]}
Classification: {json.dumps(classification, default=str)[:400]}

Respond with this exact JSON (no extra text):
{{
  "what_happened": "One clear sentence describing the event",
  "why_suspicious": "2-3 sentences explaining why this is suspicious",
  "false_positive_likelihood": "low",
  "false_positive_reason": "Brief reason for the FP likelihood",
  "recommended_action": "1-2 sentences on what to do next",
  "confidence_explanation": "Brief explanation of the confidence score"
}}"""

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_msg),
                HumanMessage(content=user_msg),
            ])
            content = response.content.strip()
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(content[start:end])
                explanation = AlertExplanation(
                    what_happened=data.get("what_happened", ""),
                    why_suspicious=data.get("why_suspicious", ""),
                    false_positive_likelihood=data.get("false_positive_likelihood", "low"),
                    false_positive_reason=data.get("false_positive_reason", ""),
                    recommended_action=data.get("recommended_action", ""),
                    confidence_explanation=data.get("confidence_explanation", ""),
                )
                _fire_blue_audit(
                    action="agent_decision",
                    incident_id=event.get("event_id") or "unknown",
                    reasoning=response.content,
                    confidence=float(classification.get("confidence", 0.5)),
                    metadata={
                        "decision_type": "alert_explained",
                        "threat_type": classification.get("threat_type"),
                        "source_ip": event.get("source_ip"),
                        "via": "claude",
                    },
                )
                return explanation
        except Exception as exc:
            logger.warning("blue_agent_explain_error", error=str(exc))

        threat_type = classification.get("threat_type", "unknown")
        return AlertExplanation(
            what_happened=f"A {threat_type} event was detected from {event.get('source_ip', 'unknown')} targeting {event.get('dest_ip', 'unknown')}.",
            why_suspicious=f"This event matches the {threat_type} pattern with confidence {classification.get('confidence', 0):.0%}. The traffic characteristics are consistent with known threat actor TTPs.",
            false_positive_likelihood="low" if classification.get("confidence", 0) > 0.7 else "medium",
            false_positive_reason="High confidence rule match with known malicious indicators." if classification.get("confidence", 0) > 0.7 else "Moderate confidence; verify manually.",
            recommended_action="Escalate to Tier 2 for investigation. Block source IP at perimeter as precaution.",
            confidence_explanation=f"Confidence {classification.get('confidence', 0):.0%} based on rule engine score and anomaly detection.",
        )

    # ── triage_alert ──────────────────────────────────────────────────────────

    async def triage_alert(
        self,
        event: dict,
        classification: dict,
    ) -> TriageDecision:
        """Quick triage decision for a single alert."""
        system_msg = (
            "You are a tier-1 SOC analyst performing rapid alert triage. "
            "Make fast, decisive triage decisions. Always respond in valid JSON."
        )
        user_msg = f"""Triage this alert quickly:

Source: {event.get('source_ip')} → {event.get('dest_ip')}
Threat type: {classification.get('threat_type')}
Severity: {classification.get('severity')}
Confidence: {classification.get('confidence')}
Is FP: {classification.get('is_false_positive')}
Rules: {classification.get('rule_matches', [])}

Respond with this exact JSON (no extra text):
{{
  "decision": "escalate",
  "reason": "One sentence reason",
  "priority": 2,
  "assigned_to": "tier2",
  "sla_minutes": 30
}}"""

        try:
            response = await self.fast_llm.ainvoke([
                SystemMessage(content=system_msg),
                HumanMessage(content=user_msg),
            ])
            content = response.content.strip()
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(content[start:end])
                triage = TriageDecision(
                    decision=data.get("decision", "investigate"),
                    reason=data.get("reason", ""),
                    priority=int(data.get("priority", 3)),
                    assigned_to=data.get("assigned_to", "tier2"),
                    sla_minutes=int(data.get("sla_minutes", 60)),
                )
                _fire_blue_audit(
                    action="agent_decision",
                    incident_id=event.get("event_id") or "unknown",
                    reasoning=response.content,
                    confidence=float(classification.get("confidence", 0.5)),
                    metadata={
                        "decision_type": "triage",
                        "triage_decision": triage.decision,
                        "priority": triage.priority,
                        "assigned_to": triage.assigned_to,
                        "threat_type": classification.get("threat_type"),
                        "via": "claude",
                    },
                )
                return triage
        except Exception as exc:
            logger.warning("blue_agent_triage_error", error=str(exc))

        # Fallback triage logic
        sev = classification.get("severity", "MEDIUM")
        is_fp = classification.get("is_false_positive", False)
        conf = float(classification.get("confidence", 0.5))

        if is_fp or conf < 0.3:
            return TriageDecision(decision="close", reason="Low confidence or known false positive.", priority=5, assigned_to="tier1", sla_minutes=240)
        if sev == "CRITICAL":
            return TriageDecision(decision="escalate", reason=f"CRITICAL severity {classification.get('threat_type')} requires immediate response.", priority=1, assigned_to="tier3", sla_minutes=15)
        if sev == "HIGH":
            return TriageDecision(decision="escalate", reason=f"HIGH severity threat {classification.get('threat_type')} detected.", priority=2, assigned_to="tier2", sla_minutes=30)
        return TriageDecision(decision="investigate", reason="Medium confidence alert requires manual review.", priority=3, assigned_to="tier2", sla_minutes=60)

    # ── Legacy compat ─────────────────────────────────────────────────────────

    async def analyze_incident(self, incident: dict | list, classification_results: list | None = None) -> "str | IncidentAnalysis":
        """Backward-compatible overload accepting dict or list."""
        if isinstance(incident, dict):
            # Old API: single incident dict → return text analysis
            events = incident.get("raw_events", [])
            classifications = [{"threat_type": "unknown", "is_threat": True, "severity": incident.get("severity", "HIGH"), "confidence": 0.8}]
            result = await self._analyze_events(events, classifications)
            return result.threat_summary
        # New API
        return await self._analyze_events(incident, classification_results or [])

    async def _analyze_events(
        self,
        events: list[dict],
        classification_results: list[dict],
    ) -> IncidentAnalysis:
        source_ips = list({e.get("source_ip") for e in events if e.get("source_ip")})[:5]
        dest_ips = list({e.get("dest_ip") for e in events if e.get("dest_ip")})[:5]
        threat_types = list({c.get("threat_type") for c in classification_results if c.get("is_threat")})
        severities = [c.get("severity", "LOW") for c in classification_results]

        system_msg = (
            "You are a senior SOC analyst with 10 years experience. "
            "Analyze security incidents precisely and concisely. Always respond in valid JSON."
        )
        user_msg = f"""Analyze this security incident:

Events: {len(events)} total events
Source IPs: {source_ips}
Destination IPs: {dest_ips}
Threat types detected: {threat_types}
Severity distribution: {severities[:10]}
Sample event: {json.dumps(events[0] if events else {{}}, default=str)[:400]}

Respond with this exact JSON (no extra text):
{{
  "severity": "HIGH",
  "threat_summary": "2-3 sentence summary of what is happening",
  "attack_chain": ["Step 1", "Step 2", "Step 3", "Step 4"],
  "affected_assets": ["10.0.1.50"],
  "root_cause": "One sentence root cause",
  "business_impact": "One sentence business impact",
  "confidence": 0.85,
  "recommended_priority": "immediate"
}}"""

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_msg),
                HumanMessage(content=user_msg),
            ])
            content = response.content.strip()
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(content[start:end])
                return IncidentAnalysis(
                    incident_id=str(uuid.uuid4()),
                    severity=data.get("severity", "HIGH"),
                    threat_summary=data.get("threat_summary", ""),
                    attack_chain=data.get("attack_chain", []),
                    affected_assets=data.get("affected_assets", source_ips),
                    root_cause=data.get("root_cause", ""),
                    business_impact=data.get("business_impact", ""),
                    confidence=float(data.get("confidence", 0.8)),
                    recommended_priority=data.get("recommended_priority", "high"),
                )
        except Exception as exc:
            logger.warning("blue_agent_analyze_error", error=str(exc))

        return _fallback_incident_analysis(events, classification_results)

    async def generate_playbook(self, incident: "dict | IncidentAnalysis", environment_context: dict | None = None) -> "dict | ResponsePlaybook":
        """Backward-compatible overload."""
        if isinstance(incident, dict):
            # Old API: dict incident → return dict playbook
            fake = _fallback_incident_analysis([], [{"threat_type": incident.get("category", "brute_force"), "is_threat": True, "severity": incident.get("severity", "HIGH"), "confidence": 0.8}])
            fake.threat_summary = incident.get("title", "Security Incident")
            pb = await self._generate_playbook_internal(fake, environment_context)
            # Return as dict for backward compat
            return {
                "id": pb.playbook_id,
                "title": pb.title,
                "phases": [{"name": p.phase_name, "steps": [{"action": s.title, "command": s.commands[0] if s.commands else None} for s in p.steps]} for p in pb.phases],
            }
        return await self._generate_playbook_internal(incident, environment_context)

    async def _generate_playbook_internal(
        self,
        incident: IncidentAnalysis,
        environment_context: dict | None = None,
    ) -> ResponsePlaybook:
        env = environment_context or {"os_mix": "Windows/Linux", "has_edr": True, "has_siem": True}
        # Reuse the public generate_playbook logic
        # (call via the BlueAgent.generate_playbook new-style path)
        threat_type = "brute_force"
        if incident.threat_summary:
            for tt in ("lateral_movement", "c2_beacon", "data_exfiltration", "brute_force"):
                if tt.replace("_", " ") in incident.threat_summary.lower():
                    threat_type = tt
                    break

        pb = _fallback_playbook(incident, threat_type, env)
        self._store_playbook(pb)
        return pb
