"""
Real public security dataset support for ThreatVision.

Datasets:
- NSL-KDD: classic IDS benchmark, 41 features, 5 attack categories
- UNSW-NB15: modern network traffic, 49 features, 9 attack categories

Usage:
    python3 -m app.datasets download     # download all datasets
    python3 -m app.datasets benchmark    # train + evaluate on both
"""
