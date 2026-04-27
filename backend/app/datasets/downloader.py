"""
Dataset downloader with progress logging and fallback mirrors.
"""
import httpx
import asyncio
from pathlib import Path
import structlog
from app.datasets.registry import get_dataset, CACHE_DIR, DATASETS

logger = structlog.get_logger(__name__)

# Fallback mirrors used when primary URLs fail
_FALLBACK_URLS: dict[str, list[str]] = {
    "nsl_kdd": [
        "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B.txt",
        "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest%2B.txt",
    ],
    # UNSW-NB15: official UNSW cloudstor requires institutional DNS.
    # Primary (registry) is the HuggingFace parquet mirror — no fallback needed.
    "unsw_nb15": [],
}


async def download_with_progress(url: str, dest_path: Path, dataset_name: str) -> bool:
    """Stream a file to disk with periodic progress logs. Returns True on success."""
    try:
        async with httpx.AsyncClient(timeout=300.0, follow_redirects=True) as client:
            async with client.stream("GET", url) as response:
                if response.status_code != 200:
                    logger.warning(
                        "download_failed", url=url, status=response.status_code
                    )
                    return False

                total = int(response.headers.get("content-length", 0))
                downloaded = 0
                last_logged = 0

                with open(dest_path, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        f.write(chunk)
                        downloaded += len(chunk)
                        if downloaded - last_logged > 10_000_000:
                            pct = (downloaded / total * 100) if total else 0
                            logger.info(
                                "download_progress",
                                dataset=dataset_name,
                                mb=downloaded // 1_000_000,
                                pct=round(pct, 1),
                            )
                            last_logged = downloaded

                logger.info(
                    "download_complete",
                    dataset=dataset_name,
                    mb=downloaded // 1_000_000,
                    path=str(dest_path),
                )
                return True
    except Exception as e:
        logger.warning("download_exception", url=url, error=str(e))
        if dest_path.exists():
            dest_path.unlink(missing_ok=True)
        return False


def _looks_like_header(line: bytes) -> bool:
    """Return True if the line looks like a CSV header (letters, not all digits)."""
    try:
        text = line.decode("utf-8", errors="ignore").strip()
        if not text:
            return False
        first_field = text.split(",")[0]
        return not first_field.lstrip("-").replace(".", "").isdigit()
    except Exception:
        return False


async def download_dataset(dataset_id: str, force: bool = False) -> Path:
    """
    Download a dataset to the cache directory.
    Combines multiple part files into a single CSV.
    Returns path to the final cached CSV.
    """
    info = get_dataset(dataset_id)
    final_path = CACHE_DIR / info.cache_filename

    if final_path.exists() and not force:
        logger.info(
            "dataset_already_cached", dataset=info.name, path=str(final_path)
        )
        return final_path

    logger.info(
        "dataset_download_start", dataset=info.name, urls=len(info.download_urls)
    )

    fallbacks = _FALLBACK_URLS.get(dataset_id, [])
    parts: list[Path] = []

    for i, primary_url in enumerate(info.download_urls):
        part_path = CACHE_DIR / f"{dataset_id}_part_{i}.tmp"

        # Build candidate list: primary + same-index fallback
        candidates = [primary_url]
        if i < len(fallbacks):
            candidates.append(fallbacks[i])

        success = False
        for url in candidates:
            if await download_with_progress(url, part_path, info.name):
                success = True
                break

        if not success:
            # Clean up any parts already written
            for p in parts:
                p.unlink(missing_ok=True)
            raise RuntimeError(
                f"All download attempts failed for {dataset_id} part {i}. "
                "Check network connectivity or supply the file manually."
            )

        parts.append(part_path)

    # Combine parts into the final CSV, stripping duplicate headers
    logger.info("combining_parts", dataset=info.name, parts=len(parts))
    with open(final_path, "wb") as out:
        for i, part in enumerate(parts):
            with open(part, "rb") as p:
                content = p.read()

            if i > 0:
                # Strip first line if it looks like a repeated header
                first_newline = content.find(b"\n")
                if 0 < first_newline < 500 and _looks_like_header(
                    content[:first_newline]
                ):
                    content = content[first_newline + 1:]

            out.write(content)
            part.unlink()

    size_mb = final_path.stat().st_size // 1_000_000
    logger.info(
        "dataset_ready",
        dataset=info.name,
        path=str(final_path),
        size_mb=size_mb,
    )
    return final_path


async def download_all() -> dict[str, dict]:
    """Download all registered datasets. Returns a status dict per dataset."""
    results: dict[str, dict] = {}
    for ds_id in DATASETS:
        try:
            path = await download_dataset(ds_id)
            size_mb = path.stat().st_size // 1_000_000
            results[ds_id] = {"status": "ok", "path": str(path), "size_mb": size_mb}
        except Exception as e:
            logger.error("download_all_failed", dataset_id=ds_id, error=str(e))
            results[ds_id] = {"status": "failed", "error": str(e)}
    return results
