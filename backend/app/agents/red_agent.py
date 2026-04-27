"""
Red Agent — AI-powered attacker that generates realistic attack TTPs.
Uses Claude to produce contextually aware attack sequences.
Maintains ChromaDB memory to adapt strategy over time.
"""
from __future__ import annotations

import json
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import structlog
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from app.config import get_settings

logger = structlog.get_logger(__name__)

# ── Attack scenario dataclass ─────────────────────────────────────────────────

@dataclass
class AttackScenario:
    scenario_id: str
    attack_type: str
    mitre_techniques: list[str]
    target_ips: list[str]
    source_ips: list[str]
    tactics_description: str
    event_sequence: list[str]
    expected_indicators: list[str]
    difficulty: str  # "low" | "medium" | "high" | "apt"


# ── Fallback scenario templates ───────────────────────────────────────────────

_FALLBACK_SCENARIOS: dict[str, dict] = {
    "brute_force": {
        "mitre_techniques": ["T1110 - Brute Force", "T1110.001 - Password Guessing", "T1078 - Valid Accounts"],
        "tactics_description": "Attacker performs credential stuffing from Tor exit nodes targeting exposed authentication endpoints.",
        "event_sequence": [
            "1. Scan target for exposed authentication endpoints",
            "2. Load credential list from previous breaches",
            "3. Launch parallel authentication requests from rotating IPs",
            "4. Monitor for successful logins",
            "5. Establish foothold with compromised credentials",
            "6. Enumerate user privileges post-authentication",
        ],
        "expected_indicators": ["185.220.x.x source IPs", "High 401 rate", "POST /auth/login pattern", "User-Agent: python-requests"],
        "difficulty": "medium",
    },
    "c2_beacon": {
        "mitre_techniques": ["T1071.001 - Web Protocols", "T1573 - Encrypted Channel", "T1008 - Fallback Channels"],
        "tactics_description": "Implant beacons home to C2 server on periodic schedule using HTTPS to blend with normal traffic.",
        "event_sequence": [
            "1. Deploy implant on compromised host via phishing or exploit",
            "2. Implant contacts C2 using jittered beacon interval",
            "3. C2 server issues tasking via encrypted channel",
            "4. Implant exfiltrates collected data in small chunks",
            "5. Rotate C2 domains for resilience",
            "6. Establish secondary C2 channel as fallback",
        ],
        "expected_indicators": ["Self-signed TLS cert", "Regular beacon interval 45-55s", "Small payload size <1KB", "svchost.exe parent"],
        "difficulty": "high",
    },
    "lateral_movement": {
        "mitre_techniques": ["T1021.002 - SMB/Windows Admin Shares", "T1003.001 - LSASS Memory", "T1047 - WMI"],
        "tactics_description": "Post-compromise lateral movement using harvested credentials to pivot across internal network via SMB and WMI.",
        "event_sequence": [
            "1. Dump credentials from LSASS on initial foothold",
            "2. Identify internal hosts via network scan",
            "3. Authenticate to adjacent hosts via SMB ADMIN$",
            "4. Deploy persistence mechanism on each new host",
            "5. Use WMI for remote command execution",
            "6. Move toward high-value targets (DC, file servers)",
        ],
        "expected_indicators": ["Port 445 internal connections", "net.exe commands", "lsass.exe access", "wmic.exe spawning cmd"],
        "difficulty": "high",
    },
    "exfiltration": {
        "mitre_techniques": ["T1048 - Exfiltration Over Alternative Protocol", "T1041 - Exfiltration Over C2 Channel"],
        "tactics_description": "Large-scale data exfiltration of sensitive files over encrypted channels to external staging server.",
        "event_sequence": [
            "1. Identify high-value data stores on compromised hosts",
            "2. Stage data into compressed archives",
            "3. Encrypt archives with attacker public key",
            "4. Transfer in chunks to avoid data loss detection",
            "5. Verify transfer integrity on C2 side",
            "6. Wipe staging artifacts",
        ],
        "expected_indicators": ["Large bytes_sent >50MB", "External destination IP", "curl/wget command", "Compressed file names"],
        "difficulty": "medium",
    },
    "data_exfiltration": {
        "mitre_techniques": [
            "T1048 - Exfiltration Over Alternative Protocol",
            "T1041 - Exfiltration Over C2 Channel",
            "T1560 - Archive Collected Data",
            "T1071.001 - Web Protocols",
        ],
        "tactics_description": (
            "Malicious actor exfiltrates sensitive internal data (PII, credentials, source code) "
            "to attacker-controlled external servers via encrypted HTTPS/HTTP POST requests. "
            "Transfers exceed 50 MB per session to maximise data theft; destination IPs reside "
            "in Tor exit-node ranges (185.220.x.x) to obscure attribution."
        ),
        "event_sequence": [
            "1. Enumerate internal file servers and databases for high-value assets",
            "2. Compress and optionally encrypt target files into staged archives",
            "3. Initiate large outbound POST to attacker staging server over HTTPS",
            "4. Repeat in multiple sessions to transfer complete dataset",
            "5. Validate receipt on attacker side; delete local staging artefacts",
            "6. Rotate destination IPs to evade reputation-based blocking",
        ],
        "expected_indicators": [
            "bytes_sent > 50 MB to external IP",
            "Destination in 185.220.x.x Tor exit range",
            "flags: large_transfer, suspicious_destination, data_exfiltration_pattern",
            "curl.exe / certutil.exe / powershell.exe initiating POST",
            "Rule TV-007 triggered (Data Exfiltration Volume)",
        ],
        "difficulty": "medium",
    },
}

_ATTACKER_IPS = [f"185.220.101.{i}" for i in range(1, 20)] + [
    "91.108.4.55", "45.142.212.100", "185.56.80.65", "194.165.16.42",
]
_INTERNAL_IPS = [f"10.0.{s}.{h}" for s in range(1, 4) for h in range(10, 20)]
_TARGETS = ["10.0.1.50", "10.0.1.100", "10.0.1.101", "10.0.50.100"]


# ── Red Agent ─────────────────────────────────────────────────────────────────

def _fire_red_audit(
    action: str,
    target_id: str,
    reasoning: str,
    metadata: dict,
) -> None:
    """Schedule a fire-and-forget audit log entry for RedAgent decisions."""
    import asyncio
    from app.services.audit_service import log_event
    try:
        asyncio.get_running_loop().create_task(log_event(
            actor_type="agent",
            actor_id="red_agent",
            action=action,
            target_type="simulation",
            target_id=target_id,
            result="success",
            reasoning=reasoning,
            metadata=metadata,
        ))
    except RuntimeError:
        pass  # No running event loop — skip audit in test/seed context


class RedAgent:
    """AI-powered attacker that generates realistic attack TTPs."""

    def __init__(self) -> None:
        settings = get_settings()
        self.llm = ChatAnthropic(
            model="claude-opus-4-5",
            api_key=settings.anthropic_api_key,
            max_tokens=2048,
            timeout=30,
            max_retries=0,
        )
        self._chroma = self._init_chroma(settings)
        self.log: list[dict] = []

    # ── ChromaDB setup ─────────────────────────────────────────────────────────

    def _init_chroma(self, settings):
        import socket
        # Fast pre-check: is ChromaDB port open? (1-second timeout to avoid hanging)
        try:
            with socket.create_connection((settings.chroma_host, settings.chroma_port), timeout=1):
                pass
        except OSError:
            # Port not reachable — skip HttpClient, go straight to EphemeralClient
            try:
                import chromadb
                client = chromadb.EphemeralClient()
                return client.get_or_create_collection("red_agent_memory")
            except Exception as exc2:
                logger.warning("red_agent_chroma_unavailable", error=str(exc2))
                return None

        try:
            import chromadb
            client = chromadb.HttpClient(
                host=settings.chroma_host,
                port=settings.chroma_port,
            )
            client.heartbeat()
            col = client.get_or_create_collection("red_agent_memory")
            logger.info("red_agent_chroma_connected", port=settings.chroma_port)
            return col
        except Exception:
            try:
                import chromadb
                client = chromadb.EphemeralClient()
                return client.get_or_create_collection("red_agent_memory")
            except Exception as exc2:
                logger.warning("red_agent_chroma_unavailable", error=str(exc2))
                return None

    def _store_memory(self, scenario: AttackScenario, outcome: str = "pending") -> None:
        if not self._chroma:
            return
        try:
            self._chroma.upsert(
                ids=[scenario.scenario_id],
                documents=[f"{scenario.attack_type} {scenario.tactics_description}"],
                metadatas=[{
                    "attack_type": scenario.attack_type,
                    "difficulty": scenario.difficulty,
                    "outcome": outcome,
                    "techniques": json.dumps(scenario.mitre_techniques[:3]),
                }],
            )
        except Exception as exc:
            logger.warning("red_agent_memory_store_error", error=str(exc))

    def _retrieve_memory(self, attack_type: str, n: int = 3) -> list[dict]:
        if not self._chroma:
            return []
        try:
            results = self._chroma.query(
                query_texts=[attack_type],
                n_results=min(n, max(1, self._chroma.count())),
            )
            metas = results.get("metadatas", [[]])[0]
            docs = results.get("documents", [[]])[0]
            return [{"meta": m, "doc": d} for m, d in zip(metas, docs)]
        except Exception:
            return []

    # ── Core methods ───────────────────────────────────────────────────────────

    async def generate_attack_scenario(
        self,
        attack_type: str,
        target_context: dict,
        previous_attempts: list,
    ) -> AttackScenario:
        """Generate a realistic attack scenario via Claude."""

        past = self._retrieve_memory(attack_type)
        past_summary = "\n".join(f"- {p['doc'][:120]}" for p in past) if past else "No prior attempts."

        system_msg = (
            "You are an expert red team operator simulating realistic cyberattacks for security testing. "
            "Generate technically accurate attack scenarios with real TTPs used by threat actors. "
            "Always respond in valid JSON."
        )
        user_msg = f"""Generate a realistic {attack_type} attack scenario.

Target environment: {json.dumps(target_context, indent=2)}
Previous attempts: {json.dumps(previous_attempts[:3], indent=2) if previous_attempts else "None"}
Past scenarios in memory:
{past_summary}

Respond with this exact JSON structure (no extra text):
{{
  "mitre_techniques": ["T1110 - Brute Force", "..."],
  "tactics_description": "2-3 sentence narrative of the attack approach",
  "event_sequence": [
    "1. First attack step",
    "2. Second step",
    "3. Third step",
    "4. Fourth step",
    "5. Fifth step"
  ],
  "expected_indicators": ["IOC 1", "IOC 2", "IOC 3"],
  "difficulty": "medium"
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
                scenario = AttackScenario(
                    scenario_id=str(uuid.uuid4()),
                    attack_type=attack_type,
                    mitre_techniques=data.get("mitre_techniques", []),
                    target_ips=_TARGETS.copy(),
                    source_ips=random.sample(_ATTACKER_IPS, min(3, len(_ATTACKER_IPS))),
                    tactics_description=data.get("tactics_description", ""),
                    event_sequence=data.get("event_sequence", []),
                    expected_indicators=data.get("expected_indicators", []),
                    difficulty=data.get("difficulty", "medium"),
                )
                self._store_memory(scenario)
                logger.info("red_agent_scenario_generated", attack_type=attack_type, via="claude")
                _fire_red_audit(
                    action="agent_decision",
                    target_id=scenario.scenario_id,
                    reasoning=response.content,
                    metadata={
                        "decision_type": "attack_scenario_generated",
                        "attack_type": attack_type,
                        "mitre_techniques": scenario.mitre_techniques[:3],
                        "difficulty": scenario.difficulty,
                        "via": "claude",
                    },
                )
                return scenario
        except Exception as exc:
            logger.warning("red_agent_claude_error", error=str(exc))

        return self._fallback_scenario(attack_type)

    def _fallback_scenario(self, attack_type: str) -> AttackScenario:
        tmpl = _FALLBACK_SCENARIOS.get(attack_type, _FALLBACK_SCENARIOS["brute_force"])
        scenario = AttackScenario(
            scenario_id=str(uuid.uuid4()),
            attack_type=attack_type,
            mitre_techniques=tmpl["mitre_techniques"],
            target_ips=_TARGETS.copy(),
            source_ips=random.sample(_ATTACKER_IPS, 3),
            tactics_description=tmpl["tactics_description"],
            event_sequence=tmpl["event_sequence"],
            expected_indicators=tmpl["expected_indicators"],
            difficulty=tmpl["difficulty"],
        )
        self._store_memory(scenario)
        _fire_red_audit(
            action="agent_decision",
            target_id=scenario.scenario_id,
            reasoning=f"Fallback scenario: {scenario.tactics_description}",
            metadata={
                "decision_type": "attack_scenario_generated",
                "attack_type": attack_type,
                "mitre_techniques": scenario.mitre_techniques[:3],
                "difficulty": scenario.difficulty,
                "via": "fallback",
            },
        )
        return scenario

    async def generate_attack_events(
        self,
        scenario: AttackScenario,
        count: int = 20,
    ) -> list[dict]:
        """Generate normalized events matching the unified schema."""
        from app.data.synthetic_generator import generate_event_batch

        # Use scenario's attack_type to generate scenario-appropriate events
        attack_map = {
            "brute_force": "brute_force",
            "c2_beacon": "c2_beacon",
            "lateral_movement": "lateral_movement",
            "exfiltration": "data_exfiltration",
            "data_exfiltration": "data_exfiltration",
        }
        scenario_type = attack_map.get(scenario.attack_type, "brute_force")

        # Generate from synthetic generator with scenario context
        all_events = generate_event_batch(count=max(count * 4, 100), scenario_mix=True)
        typed = [e for e in all_events if e.get("scenario") == scenario_type]

        # Supplement with benign events if needed
        if len(typed) < count:
            benign = [e for e in all_events if e.get("scenario") == "benign"]
            typed.extend(benign[: count - len(typed)])

        events = typed[:count]

        # Stamp with scenario metadata
        for ev in events:
            ev["scenario_id"] = scenario.scenario_id
            if scenario.source_ips:
                ev["source_ip"] = random.choice(scenario.source_ips)

        logger.info("red_agent_events_generated", count=len(events), attack_type=scenario.attack_type)
        return events

    async def adapt_strategy(
        self,
        failed_attempts: list[dict],
        blue_defenses: list[str],
    ) -> str:
        """Generate a new attack strategy in response to blue team defenses."""
        system_msg = (
            "You are a red team operator adapting attack strategy based on blue team defenses. "
            "Be specific and technical. Suggest concrete technique changes."
        )
        user_msg = f"""The following attack attempts were detected and blocked:
{json.dumps(failed_attempts[:5], indent=2, default=str)}

Blue team defenses that caught us:
{chr(10).join(f'- {d}' for d in blue_defenses[:5])}

Suggest a revised attack strategy in 2-3 paragraphs. Focus on:
1. What to change to evade detection
2. Alternative techniques that may work better
3. Timing or obfuscation changes"""

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_msg),
                HumanMessage(content=user_msg),
            ])
            return response.content
        except Exception as exc:
            logger.warning("red_agent_adapt_error", error=str(exc))
            return (
                "Strategy adaptation: Rotate source IPs more aggressively, "
                "increase beacon jitter to 120s±30s, switch from SMB to WMI for lateral movement, "
                "and stage exfiltration during business hours to blend with normal traffic."
            )

    # ── Legacy compat (kept for existing sim_engine calls) ───────────────────

    async def generate_attack_phase(
        self,
        scenario: str,
        phase: str,
        target_network: str = "192.168.1.0/24",
    ) -> list[dict]:
        """Backward-compatible method: generate events for an attack phase."""
        sc = await self.generate_attack_scenario(
            attack_type="lateral_movement" if "lateral" in phase else "brute_force",
            target_context={"network": target_network, "phase": phase},
            previous_attempts=[],
        )
        events = await self.generate_attack_events(sc, count=5)
        for ev in events:
            ev["_phase"] = phase
            ev["_scenario"] = scenario
        return events
