"""Shared scoring constants used across the scoring and correlation modules."""

PRIORITY_LABELS = [
    ("INVESTIGATE_NOW",  0.80),
    ("INVESTIGATE_SOON", 0.55),
    ("MONITOR",          0.30),
    ("LOW_PRIORITY",     0.00),
]
