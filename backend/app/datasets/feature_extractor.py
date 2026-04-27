"""
Maps dataset-specific columns to the 8-feature schema used by AnomalyDetector.

Features: bytes_sent, bytes_recv, duration_ms, source_port, dest_port,
          hour_of_day, is_external_dest, is_known_port
"""
import pandas as pd
import numpy as np

KNOWN_PORTS = {80, 443, 22, 53, 25, 123, 3306, 5432}

_SERVICE_TO_PORT: dict[str, int] = {
    "http": 80, "https": 443, "ssh": 22, "ftp": 21, "ftp_data": 20,
    "smtp": 25, "domain": 53, "domain_u": 53, "telnet": 23,
    "pop_3": 110, "imap4": 143, "finger": 79, "auth": 113,
    "time": 37, "nntp": 119, "ntp_u": 123, "snmp": 161,
    "bgp": 179, "ldap": 389, "login": 513, "shell": 514,
    "printer": 515, "exec": 512, "efs": 520, "uucp": 540,
    "klogin": 543, "kshell": 544, "hostnames": 101, "csnet_ns": 105,
    "supdup": 95, "sql_net": 1521, "vmnet": 175, "urp_i": 0,
    "tim_i": 0, "red_i": 0, "pm_dump": 0, "icmp": 0,
    "eco_i": 0, "ecr_i": 0, "other": 0, "private": 0,
    "X11": 6000, "Z39_50": 210,
}


# ── NSL-KDD ───────────────────────────────────────────────────────────────────


def extract_features_nsl_kdd(df: pd.DataFrame) -> pd.DataFrame:
    """Map NSL-KDD columns → 8-feature schema + is_attack + attack_category."""
    rng = np.random.default_rng(seed=42)
    n = len(df)

    features = pd.DataFrame()
    features["bytes_sent"] = pd.to_numeric(df["src_bytes"], errors="coerce").fillna(0).clip(lower=0)
    features["bytes_recv"] = pd.to_numeric(df["dst_bytes"], errors="coerce").fillna(0).clip(lower=0)
    # NSL-KDD duration is in seconds
    features["duration_ms"] = (
        pd.to_numeric(df["duration"], errors="coerce").fillna(0) * 1000
    ).clip(lower=0)
    # NSL-KDD has no port columns — derive dest_port from service
    features["dest_port"] = (
        df["service"]
        .map(lambda s: _SERVICE_TO_PORT.get(str(s).strip().lower(), 0))
        .fillna(0)
        .astype(int)
    )
    # Source port: ephemeral range (realistic for client-initiated connections)
    features["source_port"] = rng.integers(32768, 65535, size=n)
    # NSL-KDD has no timestamps — randomise hour uniformly
    features["hour_of_day"] = rng.integers(0, 24, size=n)
    # All NSL-KDD records are network-boundary by definition
    features["is_external_dest"] = 1
    features["is_known_port"] = features["dest_port"].apply(
        lambda p: 1 if p in KNOWN_PORTS else 0
    )
    features["is_attack"] = df["is_attack"].values
    features["attack_category"] = df["attack_category"].values
    return features.reset_index(drop=True)


# ── UNSW-NB15 ─────────────────────────────────────────────────────────────────


def _col(df: pd.DataFrame, *candidates: str) -> pd.Series:
    """Return the first existing column from candidates, or a zero Series."""
    for c in candidates:
        if c in df.columns:
            return df[c]
    return pd.Series(0, index=df.index)


def extract_features_unsw_nb15(df: pd.DataFrame) -> pd.DataFrame:
    """
    Map UNSW-NB15 columns → 8-feature schema + is_attack + attack_category.

    Handles both schema variants:
      • HuggingFace parquet: source_port / destination_port / stime
      • Original CSV:        sport / dsport / Stime
    """
    rng = np.random.default_rng(seed=42)
    n = len(df)

    features = pd.DataFrame()
    features["bytes_sent"] = (
        pd.to_numeric(_col(df, "sbytes", "src_bytes"), errors="coerce")
        .fillna(0).clip(lower=0)
    )
    features["bytes_recv"] = (
        pd.to_numeric(_col(df, "dbytes", "dst_bytes"), errors="coerce")
        .fillna(0).clip(lower=0)
    )
    features["duration_ms"] = (
        pd.to_numeric(_col(df, "dur", "duration"), errors="coerce").fillna(0) * 1000
    ).clip(lower=0)
    # HF parquet uses full names; original CSV uses abbreviated names
    features["source_port"] = (
        pd.to_numeric(_col(df, "source_port", "sport", "src_port"), errors="coerce")
        .fillna(0).astype(int).clip(0, 65535)
    )
    features["dest_port"] = (
        pd.to_numeric(_col(df, "destination_port", "dsport", "dport", "dst_port"), errors="coerce")
        .fillna(0).astype(int).clip(0, 65535)
    )
    # Timestamp: epoch seconds → hour-of-day
    stime_col = next((c for c in ("stime", "Stime", "ltime", "Ltime") if c in df.columns), None)
    if stime_col:
        features["hour_of_day"] = (
            pd.to_numeric(df[stime_col], errors="coerce")
            .fillna(0).astype(int) % 86400 // 3600
        )
    else:
        features["hour_of_day"] = rng.integers(0, 24, size=n)
    features["is_external_dest"] = 1
    features["is_known_port"] = features["dest_port"].apply(
        lambda p: 1 if p in KNOWN_PORTS else 0
    )
    features["is_attack"] = df["is_attack"].values
    features["attack_category"] = df["attack_category"].values
    return features.reset_index(drop=True)


# ── Universal ─────────────────────────────────────────────────────────────────


def extract_features(dataset_id: str, df: pd.DataFrame) -> pd.DataFrame:
    """Extract our 8-feature schema from any registered dataset DataFrame."""
    if dataset_id == "nsl_kdd":
        return extract_features_nsl_kdd(df)
    elif dataset_id == "unsw_nb15":
        return extract_features_unsw_nb15(df)
    else:
        raise ValueError(f"Unknown dataset: {dataset_id}")
