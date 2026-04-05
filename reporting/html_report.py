"""HTML report generation — implemented in Phase 4."""
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def render_report(triage_results: list, output_path: str, config: dict) -> str:
    """Render an HTML triage report from a list of TriageResult objects.

    Args:
        triage_results: List of TriageResult instances, sorted by descending score.
        output_path: Destination file path for the rendered HTML file.
        config: Reporting config section dict (max_alerts_in_report, highlight_top_n, etc.).

    Returns:
        Absolute path to the written HTML file.
    """
    raise NotImplementedError("HTML report rendering is implemented in Phase 4")


def load_template(template_path: str) -> str:
    """Read and return the raw Jinja2 HTML template string.

    Args:
        template_path: Path to the report.html template file.

    Returns:
        Raw template string ready for rendering.
    """
    raise NotImplementedError("Template loading is implemented in Phase 4")
