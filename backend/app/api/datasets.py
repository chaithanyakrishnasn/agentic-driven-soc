"""
Dataset management API — download, train, benchmark, and replay real public security datasets.

Route ordering rule (CLAUDE.md): static paths MUST be registered before /{id} wildcards.
"""
import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException

from app.datasets.benchmark import evaluate_on_dataset, train_on_dataset
from app.datasets.downloader import download_dataset
from app.datasets.registry import DATASETS, get_dataset, is_cached, list_datasets
from app.detection.anomaly_detector import AnomalyDetector

logger = structlog.get_logger(__name__)
router = APIRouter()

# Module-level caches (in-memory, intentional — mirrors playbook/simulation pattern)
_trained_detectors: dict[str, AnomalyDetector] = {}
_last_benchmark: dict[str, dict] = {}


# ══════════════════════════════════════════════════════════════════════════════
#  STATIC ROUTES — must come before /{dataset_id} wildcards
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/")
async def list_available_datasets():
    """List all registered datasets with download/training/benchmark status."""
    return [
        {
            "id": ds.id,
            "name": ds.name,
            "description": ds.description,
            "size_mb": ds.size_mb,
            "record_count": ds.record_count,
            "feature_count": ds.feature_count,
            "attack_categories": ds.attack_categories,
            "license": ds.license,
            "cached": is_cached(ds.id),
            "trained": ds.id in _trained_detectors,
            "last_benchmark": _last_benchmark.get(ds.id),
        }
        for ds in list_datasets()
    ]


@router.get("/benchmarks/summary")
async def get_benchmark_summary():
    """Return latest benchmark results for all datasets — used by dashboard card."""
    summary = []
    for ds_id, info in DATASETS.items():
        summary.append({
            "dataset_id": ds_id,
            "name": info.name,
            "samples": info.record_count,
            "cached": is_cached(ds_id),
            "benchmark": _last_benchmark.get(ds_id),
        })
    return summary


@router.get("/replay/status")
async def replay_status():
    """Get current replay status and cumulative stats."""
    from app.datasets.replay import get_replayer
    return get_replayer().get_status()


@router.post("/replay/stop")
async def stop_replay():
    """Stop the active dataset replay."""
    from app.datasets.replay import get_replayer
    return await get_replayer().stop_replay()


# ══════════════════════════════════════════════════════════════════════════════
#  WILDCARD ROUTES — /{dataset_id}/...
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/{dataset_id}/download")
async def trigger_download(dataset_id: str, background_tasks: BackgroundTasks):
    """Trigger dataset download as a background task."""
    try:
        info = get_dataset(dataset_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    if is_cached(dataset_id):
        return {"status": "already_cached", "dataset_id": dataset_id}

    async def _download() -> None:
        try:
            await download_dataset(dataset_id)
        except Exception as e:
            logger.error("background_download_failed", dataset_id=dataset_id, error=str(e))

    background_tasks.add_task(_download)
    return {
        "status": "downloading",
        "dataset_id": dataset_id,
        "size_mb": info.size_mb,
        "message": f"Downloading {info.name} (~{info.size_mb} MB) in background.",
    }


@router.post("/{dataset_id}/train")
async def trigger_training(dataset_id: str, sample_size: int = 50_000):
    """
    Train IsolationForest on the specified dataset.
    Synchronous — takes ~10-30 s depending on sample_size.
    """
    try:
        get_dataset(dataset_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    if not is_cached(dataset_id):
        raise HTTPException(
            status_code=400,
            detail=f"Dataset '{dataset_id}' not downloaded. Call POST /{dataset_id}/download first.",
        )

    detector = train_on_dataset(dataset_id, sample_size=sample_size)
    _trained_detectors[dataset_id] = detector

    return {
        "status": "trained",
        "dataset_id": dataset_id,
        "samples_used": sample_size,
        "features": detector.feature_names,
    }


@router.post("/{dataset_id}/benchmark")
async def trigger_benchmark(dataset_id: str, sample_size: int = 20_000):
    """
    Evaluate the trained detector against ground-truth labels.
    Requires /train to have been called first.
    """
    try:
        get_dataset(dataset_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    if dataset_id not in _trained_detectors:
        raise HTTPException(
            status_code=400,
            detail=f"No trained detector for '{dataset_id}'. Call POST /{dataset_id}/train first.",
        )

    result = evaluate_on_dataset(
        _trained_detectors[dataset_id], dataset_id, sample_size=sample_size
    )
    _last_benchmark[dataset_id] = result
    return result


@router.post("/{dataset_id}/replay/start")
async def start_replay(
    dataset_id: str,
    events_per_second: int = 5,
    sample_size: int = 1_000,
):
    """Start streaming real dataset records through the live ingestion pipeline."""
    try:
        get_dataset(dataset_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    if not is_cached(dataset_id):
        raise HTTPException(
            status_code=400,
            detail=f"Dataset '{dataset_id}' not downloaded. Call POST /{dataset_id}/download first.",
        )

    from app.datasets.replay import get_replayer
    return await get_replayer().start_replay(dataset_id, events_per_second, sample_size)


@router.get("/{dataset_id}/status")
async def get_dataset_status(dataset_id: str):
    """Get current download/training/benchmark status for a single dataset."""
    try:
        info = get_dataset(dataset_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {
        "dataset_id": dataset_id,
        "name": info.name,
        "cached": is_cached(dataset_id),
        "trained": dataset_id in _trained_detectors,
        "last_benchmark": _last_benchmark.get(dataset_id),
    }
