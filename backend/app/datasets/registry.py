"""
Central registry of available public security datasets.
"""
from dataclasses import dataclass, field
from pathlib import Path

CACHE_DIR = Path(__file__).parent / "cache"
CACHE_DIR.mkdir(exist_ok=True)


@dataclass
class DatasetInfo:
    id: str
    name: str
    description: str
    size_mb: int
    record_count: int
    feature_count: int
    attack_categories: list[str]
    download_urls: list[str]
    cache_filename: str
    license: str


DATASETS: dict[str, DatasetInfo] = {
    "nsl_kdd": DatasetInfo(
        id="nsl_kdd",
        name="NSL-KDD",
        description="Refined KDD Cup 1999 dataset — classic IDS benchmark with 41 network features and 5 attack categories",
        size_mb=5,
        record_count=125973,
        feature_count=41,
        attack_categories=["dos", "probe", "r2l", "u2r", "normal"],
        download_urls=[
            "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt",
            "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt",
        ],
        cache_filename="nsl_kdd_combined.csv",
        license="Public — University of New Brunswick",
    ),
    "unsw_nb15": DatasetInfo(
        id="unsw_nb15",
        name="UNSW-NB15",
        description="Modern network traffic dataset with 9 attack categories and 49 features — generated at UNSW Canberra",
        size_mb=175,
        record_count=2540044,
        feature_count=49,
        attack_categories=[
            "normal", "fuzzers", "analysis", "backdoors", "dos",
            "exploits", "generic", "reconnaissance", "shellcode", "worms",
        ],
        # Primary: HuggingFace mirror (single parquet, publicly accessible)
        # Original UNSW cloudstor requires institutional DNS access
        download_urls=[
            "https://huggingface.co/datasets/rdpahalavan/UNSW-NB15/resolve/main/Network-Flows/UNSW_Flow.parquet",
        ],
        cache_filename="unsw_nb15_combined.parquet",
        license="Public — UNSW Canberra Cyber",
    ),
}


def get_dataset(dataset_id: str) -> DatasetInfo:
    if dataset_id not in DATASETS:
        raise ValueError(
            f"Unknown dataset: {dataset_id}. Available: {list(DATASETS.keys())}"
        )
    return DATASETS[dataset_id]


def list_datasets() -> list[DatasetInfo]:
    return list(DATASETS.values())


def is_cached(dataset_id: str) -> bool:
    info = get_dataset(dataset_id)
    cache_path = CACHE_DIR / info.cache_filename
    return cache_path.exists() and cache_path.stat().st_size > 0
