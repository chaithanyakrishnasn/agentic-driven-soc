"""
Loaders for NSL-KDD and UNSW-NB15 datasets.
Each loader returns a DataFrame with normalised columns including
`attack_category` and `is_attack`.
"""
import pandas as pd
import structlog
from app.datasets.registry import get_dataset, CACHE_DIR

logger = structlog.get_logger(__name__)

# ── NSL-KDD ───────────────────────────────────────────────────────────────────

NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]

NSL_KDD_ATTACK_MAP: dict[str, str] = {
    # DoS
    "back": "dos", "land": "dos", "neptune": "dos", "pod": "dos",
    "smurf": "dos", "teardrop": "dos", "mailbomb": "dos", "apache2": "dos",
    "processtable": "dos", "udpstorm": "dos",
    # Probe
    "ipsweep": "probe", "nmap": "probe", "portsweep": "probe", "satan": "probe",
    "mscan": "probe", "saint": "probe",
    # R2L
    "ftp_write": "r2l", "guess_passwd": "r2l", "imap": "r2l", "multihop": "r2l",
    "phf": "r2l", "spy": "r2l", "warezclient": "r2l", "warezmaster": "r2l",
    "sendmail": "r2l", "named": "r2l", "snmpgetattack": "r2l", "snmpguess": "r2l",
    "xlock": "r2l", "xsnoop": "r2l", "worm": "r2l",
    # U2R
    "buffer_overflow": "u2r", "loadmodule": "u2r", "perl": "u2r", "rootkit": "u2r",
    "httptunnel": "u2r", "ps": "u2r", "sqlattack": "u2r", "xterm": "u2r",
    # Normal
    "normal": "normal",
}


def load_nsl_kdd(sample_size: int | None = None) -> pd.DataFrame:
    """Load NSL-KDD combined CSV. Returns DataFrame with attack_category / is_attack."""
    info = get_dataset("nsl_kdd")
    path = CACHE_DIR / info.cache_filename
    if not path.exists():
        raise FileNotFoundError(
            f"NSL-KDD not cached at {path}. Run: python3 -m app.datasets download"
        )

    df = pd.read_csv(path, names=NSL_KDD_COLUMNS, header=None)

    df["attack_category"] = df["label"].map(
        lambda x: NSL_KDD_ATTACK_MAP.get(str(x).strip().lower(), "unknown")
    )
    df["is_attack"] = (df["attack_category"] != "normal").astype(int)

    if sample_size and len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)

    logger.info(
        "nsl_kdd_loaded",
        rows=len(df),
        attacks=int(df["is_attack"].sum()),
        categories=df["attack_category"].value_counts().to_dict(),
    )
    return df


# ── UNSW-NB15 ─────────────────────────────────────────────────────────────────


def load_unsw_nb15(sample_size: int | None = None) -> pd.DataFrame:
    """
    Load UNSW-NB15 dataset (parquet or CSV).
    Returns DataFrame with attack_category / is_attack.

    Handles two schema variants:
      • HuggingFace parquet (rdpahalavan/UNSW-NB15): columns attack_label / binary_label
      • Original UNSW CSV: columns attack_cat / label
    """
    info = get_dataset("unsw_nb15")
    path = CACHE_DIR / info.cache_filename
    if not path.exists():
        raise FileNotFoundError(
            f"UNSW-NB15 not cached at {path}. Run: python3 -m app.datasets download"
        )

    suffix = path.suffix.lower()
    if suffix == ".parquet":
        df = pd.read_parquet(path)
    else:
        df = pd.read_csv(path, low_memory=False)

    # Normalise label column (HF parquet uses 'attack_label' / 'binary_label')
    if "attack_label" in df.columns:
        df["attack_category"] = df["attack_label"].fillna("Normal").str.lower().str.strip()
    elif "attack_cat" in df.columns:
        df["attack_category"] = df["attack_cat"].fillna("Normal").str.lower().str.strip()
    else:
        logger.warning("unsw_unexpected_schema", columns=list(df.columns)[:15])
        df["attack_category"] = "normal"

    # Unify blank entries
    df.loc[df["attack_category"].isin(["", " "]), "attack_category"] = "normal"

    if "binary_label" in df.columns:
        df["is_attack"] = pd.to_numeric(df["binary_label"], errors="coerce").fillna(0).astype(int)
    elif "label" in df.columns:
        df["is_attack"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
    else:
        df["is_attack"] = (df["attack_category"] != "normal").astype(int)

    if sample_size and len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)

    logger.info(
        "unsw_nb15_loaded",
        rows=len(df),
        attacks=int(df["is_attack"].sum()),
        categories=df["attack_category"].value_counts().to_dict(),
    )
    return df


# ── Universal loader ──────────────────────────────────────────────────────────


def load_dataset(dataset_id: str, sample_size: int | None = None) -> pd.DataFrame:
    """Load any registered dataset by ID."""
    if dataset_id == "nsl_kdd":
        return load_nsl_kdd(sample_size)
    elif dataset_id == "unsw_nb15":
        return load_unsw_nb15(sample_size)
    else:
        raise ValueError(f"Unknown dataset: {dataset_id}")
