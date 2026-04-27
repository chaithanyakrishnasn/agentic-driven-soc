"""
Replay real dataset records as live events through the ingestion pipeline.
Records are converted to NormalizedEvent format and pushed to the Redis stream
so they flow through the full classification → persistence → WebSocket path.
"""
from __future__ import annotations

import asyncio
import random
import uuid
from datetime import datetime, timezone

import structlog

from app.datasets.feature_extractor import extract_features
from app.datasets.loaders import load_dataset

logger = structlog.get_logger(__name__)

# Map dataset attack categories → ThreatVision scenario labels
_ATTACK_TO_SCENARIO: dict[str, str] = {
    "dos":             "data_exfiltration",
    "probe":           "lateral_movement",
    "r2l":             "brute_force",
    "u2r":             "lateral_movement",
    "fuzzers":         "brute_force",
    "exploits":        "lateral_movement",
    "reconnaissance":  "lateral_movement",
    "shellcode":       "c2_beacon",
    "backdoors":       "c2_beacon",
    "backdoor":        "c2_beacon",
    "analysis":        "lateral_movement",
    "generic":         "data_exfiltration",
    "worms":           "lateral_movement",
    "normal":          "benign",
    "benign":          "benign",
}

_TOR_PREFIXES = ["185.220.101.", "185.220.102.", "185.220.100."]
_INTERNAL_SUBNETS = ["10.0.1.", "10.0.2.", "10.0.3."]


def _make_event(row, dataset_id: str) -> dict:
    """Convert a feature-extracted row to a NormalizedEvent-compatible dict."""
    attack_cat   = str(row.get("attack_category", "benign")).lower().strip()
    is_attack    = bool(row.get("is_attack", 0))
    scenario     = _ATTACK_TO_SCENARIO.get(attack_cat, "benign")

    # Build realistic IPs based on scenario
    if scenario == "benign":
        src_ip  = f"10.0.{random.randint(1, 3)}.{random.randint(10, 200)}"
        dst_ip  = f"10.0.{random.randint(1, 3)}.{random.randint(10, 200)}"
    elif scenario == "brute_force":
        src_ip  = random.choice(_TOR_PREFIXES) + str(random.randint(1, 254))
        dst_ip  = "10.0.1.50"                       # auth-server
    elif scenario == "c2_beacon":
        src_ip  = "10.0.2.87"                       # c2-infected-host
        dst_ip  = f"91.108.4.{random.randint(1, 254)}"
    elif scenario == "lateral_movement":
        src_ip  = f"10.0.2.{random.randint(80, 99)}"
        dst_ip  = f"10.0.1.{random.randint(100, 150)}"
    else:
        src_ip  = random.choice(_TOR_PREFIXES) + str(random.randint(1, 254))
        dst_ip  = f"10.0.1.{random.randint(1, 254)}"

    flags: list[str] = [f"dataset:{dataset_id}", f"category:{attack_cat}"]
    if scenario == "brute_force":
        flags += ["tor_exit_node", "brute_force_pattern"]
    elif scenario == "c2_beacon":
        flags += ["c2_beacon", "self_signed_cert"]
    elif scenario == "lateral_movement":
        flags += ["lateral_movement", "smb_traversal"]

    return {
        "event_id":     str(uuid.uuid4()),
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "layer":        "network",
        "source_ip":    src_ip,
        "dest_ip":      dst_ip,
        "source_port":  int(row.get("source_port", 0)),
        "dest_port":    int(row.get("dest_port", 0)),
        "protocol":     "tcp",
        "bytes_sent":   int(row.get("bytes_sent", 0)),
        "bytes_recv":   int(row.get("bytes_recv", 0)),
        "duration_ms":  int(row.get("duration_ms", 0)),
        "process_name": None,
        "parent_process": None,
        "user":         None,
        "http_method":  None,
        "http_endpoint": None,
        "http_status":  None,
        "user_agent":   None,
        "geo_country":  None,   # normalizer will enrich from source_ip
        "flags":        flags,
        "scenario":     scenario,
        "severity":     "CRITICAL" if attack_cat in ("u2r", "shellcode", "backdoor", "backdoors")
                        else "HIGH" if is_attack else "LOW",
        "confidence":   0.9 if is_attack else 0.1,
        "raw_payload":  {"dataset": dataset_id, "category": attack_cat, "is_attack": is_attack},
    }


class DatasetReplayer:
    """Replays a real dataset as live events through the ingestion pipeline."""

    def __init__(self) -> None:
        self._producer = None          # lazy-init EventProducer
        self._task: asyncio.Task | None = None
        self._running = False
        self._current_dataset: str | None = None
        self._stats: dict = self._blank_stats()

    @staticmethod
    def _blank_stats() -> dict:
        return {
            "events_replayed":  0,
            "attacks_replayed": 0,
            "started_at":       None,
            "dataset":          None,
            "events_per_second": 0,
        }

    async def _ensure_producer(self) -> None:
        if self._producer is None:
            from app.ingestion.redis_consumer import EventProducer
            self._producer = EventProducer()
            await self._producer.connect()

    # ── Public API ────────────────────────────────────────────────────────────

    async def start_replay(
        self,
        dataset_id: str,
        events_per_second: int = 5,
        sample_size: int = 1_000,
        loop_forever: bool = True,
    ) -> dict:
        """Start replaying a dataset in a background task. Returns immediately."""
        if self._running:
            await self.stop_replay()

        await self._ensure_producer()

        self._running = True
        self._current_dataset = dataset_id
        self._stats = {
            "events_replayed":   0,
            "attacks_replayed":  0,
            "started_at":        datetime.now(timezone.utc).isoformat(),
            "dataset":           dataset_id,
            "events_per_second": events_per_second,
        }

        self._task = asyncio.create_task(
            self._replay_loop(dataset_id, events_per_second, sample_size, loop_forever),
            name=f"replay-{dataset_id}",
        )
        logger.info("replay_started", dataset=dataset_id, eps=events_per_second, sample_size=sample_size)
        return {"status": "started", **self._stats}

    async def stop_replay(self) -> dict:
        """Stop the active replay and return final stats."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        logger.info("replay_stopped", **self._stats)
        return {"status": "stopped", **self._stats}

    def get_status(self) -> dict:
        return {
            "running":          self._running,
            "current_dataset":  self._current_dataset,
            **self._stats,
        }

    # ── Internal loop ─────────────────────────────────────────────────────────

    async def _replay_loop(
        self,
        dataset_id: str,
        eps: int,
        sample_size: int,
        loop_forever: bool,
    ) -> None:
        delay = 1.0 / max(eps, 1)
        try:
            df       = load_dataset(dataset_id, sample_size=sample_size)
            features = extract_features(dataset_id, df)
            rows     = features.to_dict("records")

            logger.info("replay_data_loaded", dataset=dataset_id, rows=len(rows))

            while self._running:
                for row in rows:
                    if not self._running:
                        break
                    event = _make_event(row, dataset_id)
                    try:
                        await self._producer.publish_single(event)
                        self._stats["events_replayed"] += 1
                        if event.get("scenario") != "benign":
                            self._stats["attacks_replayed"] += 1
                    except Exception as pub_err:
                        logger.warning("replay_publish_error", error=str(pub_err))
                    await asyncio.sleep(delay)

                if not loop_forever:
                    break
                logger.info(
                    "replay_loop_restart",
                    dataset=dataset_id,
                    total=self._stats["events_replayed"],
                )

        except asyncio.CancelledError:
            logger.info("replay_cancelled", dataset=dataset_id)
            raise
        except Exception as exc:
            logger.error("replay_error", dataset=dataset_id, error=str(exc))
            self._running = False


# ── Singleton ─────────────────────────────────────────────────────────────────

_replayer: DatasetReplayer | None = None


def get_replayer() -> DatasetReplayer:
    global _replayer
    if _replayer is None:
        _replayer = DatasetReplayer()
    return _replayer
