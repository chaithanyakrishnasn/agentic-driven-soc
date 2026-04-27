"""
CLI bootstrap for real dataset support.

Usage:
    python3 -m app.datasets download    # download all datasets to cache/
    python3 -m app.datasets train       # train IsolationForest on each
    python3 -m app.datasets benchmark   # train + evaluate, print metrics
    python3 -m app.datasets all         # download → train → benchmark
    python3 -m app.datasets status      # show cache status without downloading
"""
import asyncio
import json
import sys

from app.datasets.registry import DATASETS, is_cached


async def cmd_download() -> None:
    from app.datasets.downloader import download_all
    print("Downloading datasets...")
    results = await download_all()
    print(json.dumps(results, indent=2))


def cmd_train() -> None:
    from app.datasets.benchmark import train_on_dataset
    for ds_id in DATASETS:
        if not is_cached(ds_id):
            print(f"  [SKIP] {ds_id} — not cached. Run download first.")
            continue
        print(f"\n=== Training on {ds_id} ===")
        train_on_dataset(ds_id, sample_size=50_000)
        print(f"  Done.")


def cmd_benchmark() -> None:
    from app.datasets.benchmark import evaluate_on_dataset, train_on_dataset
    for ds_id in DATASETS:
        if not is_cached(ds_id):
            print(f"  [SKIP] {ds_id} — not cached. Run download first.")
            continue
        print(f"\n=== {ds_id}: Training ===")
        detector = train_on_dataset(ds_id, sample_size=50_000)
        print(f"=== {ds_id}: Evaluating ===")
        result = evaluate_on_dataset(detector, ds_id, sample_size=20_000)
        # Print summary line then full JSON
        print(
            f"  accuracy={result['accuracy']}  precision={result['precision']}"
            f"  recall={result['recall']}  f1={result['f1_score']}"
        )
        print(json.dumps(result, indent=2))


async def cmd_all() -> None:
    from app.datasets.benchmark import evaluate_on_dataset, train_on_dataset
    from app.datasets.downloader import download_all

    print("=== Step 1: Download ===")
    dl_results = await download_all()
    print(json.dumps(dl_results, indent=2))

    print("\n=== Step 2: Train + Benchmark ===")
    for ds_id in DATASETS:
        if not is_cached(ds_id):
            print(f"  [SKIP] {ds_id} — download failed, skipping.")
            continue
        detector = train_on_dataset(ds_id, sample_size=50_000)
        result = evaluate_on_dataset(detector, ds_id, sample_size=20_000)
        print(
            f"\n{ds_id}: accuracy={result['accuracy']}  f1={result['f1_score']}"
        )
        print(json.dumps(result, indent=2))


def cmd_status() -> None:
    from app.datasets.registry import CACHE_DIR
    print(f"Cache directory: {CACHE_DIR}\n")
    for ds_id, ds in DATASETS.items():
        cached = is_cached(ds_id)
        path = CACHE_DIR / ds.cache_filename
        size = f"{path.stat().st_size // 1_000_000} MB" if cached else "—"
        status = "CACHED" if cached else "NOT DOWNLOADED"
        print(f"  {ds_id:15s}  [{status}]  {size}")


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "download":
        asyncio.run(cmd_download())
    elif cmd == "train":
        cmd_train()
    elif cmd == "benchmark":
        cmd_benchmark()
    elif cmd == "all":
        asyncio.run(cmd_all())
    elif cmd == "status":
        cmd_status()
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
