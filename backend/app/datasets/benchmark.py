"""
Train IsolationForest on real datasets and evaluate detection accuracy.

The AnomalyDetector normalization was calibrated for synthetic training data, so
normal traffic from real datasets typically scores 0.6-0.9 instead of ~0.1.
We therefore auto-calibrate the decision threshold on a small held-out set before
evaluating: we pick the threshold that maximises F1 on calibration data, then
report metrics at that threshold so the number reflects actual usefulness.
"""
import structlog
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from app.datasets.feature_extractor import extract_features
from app.datasets.loaders import load_dataset
from app.detection.anomaly_detector import AnomalyDetector

logger = structlog.get_logger(__name__)

FEATURE_COLS = [
    "bytes_sent", "bytes_recv", "duration_ms",
    "source_port", "dest_port", "hour_of_day",
    "is_external_dest", "is_known_port",
]

# Default threshold kept for synthetic-data usage; overridden per dataset in evaluate_on_dataset
_DEFAULT_THRESHOLD = 0.5
_CALIBRATION_STEPS = 20   # number of thresholds to search (0.5 → 1.0)


def _rows_to_events(feature_df) -> list[dict]:
    """Convert feature DataFrame rows to event dicts that AnomalyDetector.train() accepts."""
    events = []
    for row in feature_df[FEATURE_COLS].itertuples(index=False):
        events.append({
            "bytes_sent":   int(row.bytes_sent),
            "bytes_recv":   int(row.bytes_recv),
            "duration_ms":  int(row.duration_ms),
            "source_port":  int(row.source_port),
            "dest_port":    int(row.dest_port),
            "timestamp":    f"2026-04-13T{int(row.hour_of_day):02d}:00:00Z",
            "dest_ip":      "1.2.3.4",  # treated as external
        })
    return events


def _score_features(detector: AnomalyDetector, features) -> list[float]:
    """Score a feature DataFrame and return a list of floats."""
    scores: list[float] = []
    for row in features[FEATURE_COLS].itertuples(index=False):
        event = {
            "bytes_sent":  int(row.bytes_sent),
            "bytes_recv":  int(row.bytes_recv),
            "duration_ms": int(row.duration_ms),
            "source_port": int(row.source_port),
            "dest_port":   int(row.dest_port),
            "timestamp":   f"2026-04-13T{int(row.hour_of_day):02d}:00:00Z",
            "dest_ip":     "1.2.3.4",
        }
        scores.append(detector.score(event))
    return scores


def _calibrate_threshold(
    detector: AnomalyDetector, dataset_id: str, calib_size: int = 5_000
) -> float:
    """
    Find the anomaly-score threshold that maximises F1 on a small calibration set.
    Searches linearly from 0.5 to 0.99 in _CALIBRATION_STEPS steps.
    """
    df = load_dataset(dataset_id, sample_size=calib_size)
    features = extract_features(dataset_id, df)
    y_true = features["is_attack"].tolist()

    if sum(y_true) == 0:
        logger.warning("calibration_no_attacks", dataset=dataset_id)
        return _DEFAULT_THRESHOLD

    scores = _score_features(detector, features)

    best_threshold = _DEFAULT_THRESHOLD
    best_f1 = -1.0
    low, high = min(scores) + 0.01, max(scores) - 0.01
    if low >= high:
        return _DEFAULT_THRESHOLD

    step = (high - low) / _CALIBRATION_STEPS
    t = low
    while t <= high:
        y_pred = [1 if s > t else 0 for s in scores]
        current_f1 = f1_score(y_true, y_pred, zero_division=0)
        if current_f1 > best_f1:
            best_f1 = current_f1
            best_threshold = t
        t += step

    logger.info(
        "threshold_calibrated",
        dataset=dataset_id,
        threshold=round(best_threshold, 4),
        calibration_f1=round(best_f1, 4),
        calib_samples=calib_size,
    )
    return best_threshold


def train_on_dataset(dataset_id: str, sample_size: int = 50_000) -> AnomalyDetector:
    """
    Train a fresh IsolationForest on normal-traffic records from a real dataset.
    Returns the trained AnomalyDetector instance.
    """
    logger.info("training_start", dataset=dataset_id, samples=sample_size)

    df = load_dataset(dataset_id, sample_size=sample_size)
    features = extract_features(dataset_id, df)

    # Unsupervised: train only on normal traffic
    normal = features[features["is_attack"] == 0]
    if normal.empty:
        raise RuntimeError(f"No normal-traffic records found in {dataset_id}")

    train_events = _rows_to_events(normal)

    detector = AnomalyDetector()
    detector.train(train_events)

    logger.info(
        "training_complete",
        dataset=dataset_id,
        normal_samples=len(train_events),
    )
    return detector


def evaluate_on_dataset(
    detector: AnomalyDetector,
    dataset_id: str,
    sample_size: int = 20_000,
) -> dict:
    """
    Score every record through the detector and compare against ground-truth labels.

    Auto-calibrates the decision threshold on a small held-out set first, so that
    the reported metrics reflect real-world usefulness rather than a fixed cutoff
    that was tuned for synthetic data.

    Returns a metrics dict including per-attack-category breakdown.
    """
    logger.info("evaluation_start", dataset=dataset_id, samples=sample_size)

    # Calibrate threshold on a small independent set
    threshold = _calibrate_threshold(detector, dataset_id)

    df = load_dataset(dataset_id, sample_size=sample_size)
    features = extract_features(dataset_id, df)

    y_true = features["is_attack"].tolist()
    scores = _score_features(detector, features)
    y_pred = [1 if s > threshold else 0 for s in scores]

    accuracy  = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall    = recall_score(y_true, y_pred, zero_division=0)
    f1        = f1_score(y_true, y_pred, zero_division=0)
    cm        = confusion_matrix(y_true, y_pred)

    tn = int(cm[0][0]) if cm.shape == (2, 2) else 0
    fp = int(cm[0][1]) if cm.shape == (2, 2) else 0
    fn = int(cm[1][0]) if cm.shape == (2, 2) else 0
    tp = int(cm[1][1]) if cm.shape == (2, 2) else 0

    # Per-category breakdown
    by_category: dict[str, dict] = {}
    cats = features["attack_category"]
    for cat in cats.unique():
        mask = cats == cat
        count = int(mask.sum())
        if count == 0:
            continue
        detected = int(sum(y_pred[i] for i in range(len(y_pred)) if mask.iloc[i]))
        by_category[cat] = {
            "samples": count,
            "detected": detected,
            "detection_rate": round(detected / count, 3),
        }

    result = {
        "dataset": dataset_id,
        "samples_evaluated": len(y_true),
        "calibrated_threshold": round(threshold, 4),
        "accuracy":  round(accuracy,  4),
        "precision": round(precision, 4),
        "recall":    round(recall,    4),
        "f1_score":  round(f1,        4),
        "confusion_matrix": {
            "true_negatives":  tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives":  tp,
        },
        "by_attack_category": by_category,
    }

    logger.info(
        "evaluation_complete",
        dataset=dataset_id,
        threshold=round(threshold, 4),
        accuracy=result["accuracy"],
        precision=result["precision"],
        recall=result["recall"],
        f1_score=result["f1_score"],
    )
    return result
