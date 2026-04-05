"""Alert priority scoring — implemented in Phase 3."""
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TriageResult:
    """Scored triage output for a single alert — populated in Phase 3."""

    alert_id: str
    score: float
    priority_label: str          # INVESTIGATE_NOW | INVESTIGATE_SOON | MONITOR | LOW_PRIORITY
    confidence: str              # high | medium | low
    analyst_summary: str
    score_breakdown: dict = field(default_factory=dict)


def score_alert(alert, weights: dict, severity_map: dict, confidence_thresholds: dict) -> TriageResult:
    """Compute a weighted priority score for a single enriched Alert.

    Args:
        alert: An Alert instance with enrichment fields populated.
        weights: Dict mapping component names to float weights (must sum to 1.0).
        severity_map: Dict mapping severity labels to float scores.
        confidence_thresholds: Dict with high_confidence and medium_confidence float thresholds.

    Returns:
        A TriageResult with score, priority_label, confidence, and breakdown.
    """
    raise NotImplementedError("Alert scoring is implemented in Phase 3")
