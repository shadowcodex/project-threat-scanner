"""Benchmark collector — tracks per-stage stats across a pipeline run.

Every pipeline node records its runtime, findings count, errors, and
(for agentic stages) token usage into a shared ``BenchmarkCollector``.
At pipeline end the collector writes JSON + markdown cost reports.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class StageStats:
    """Stats for a single pipeline stage."""

    name: str
    runtime_seconds: float
    findings_count: int = 0
    errors: list[str] = field(default_factory=list)
    token_usage: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_agentic(self) -> bool:
        return bool(self.token_usage)


class BenchmarkCollector:
    """Accumulates StageStats from pipeline nodes and produces reports."""

    def __init__(self) -> None:
        self.stages: list[StageStats] = []
        self._start_time: float = 0.0

    def start(self) -> None:
        """Mark the beginning of the pipeline run."""
        self._start_time = time.monotonic()

    def add(self, stats: StageStats) -> None:
        self.stages.append(stats)

    def total_runtime(self) -> float:
        return sum(s.runtime_seconds for s in self.stages)

    def total_findings(self) -> int:
        return sum(s.findings_count for s in self.stages)

    def total_errors(self) -> list[str]:
        errors: list[str] = []
        for s in self.stages:
            errors.extend(s.errors)
        return errors

    def total_token_usage(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for s in self.stages:
            for key, val in s.token_usage.items():
                totals[key] = totals.get(key, 0) + val
        return totals

    def analyst_stages(self) -> list[StageStats]:
        return [s for s in self.stages if s.name.startswith("analyst-")]

    def to_dict(self) -> dict[str, Any]:
        pipeline_total = time.monotonic() - self._start_time if self._start_time else 0.0
        return {
            "pipeline_total_seconds": round(pipeline_total, 2),
            "stages": [
                {
                    "name": s.name,
                    "runtime_seconds": round(s.runtime_seconds, 2),
                    "findings_count": s.findings_count,
                    "errors": s.errors,
                    "token_usage": s.token_usage if s.is_agentic else None,
                }
                for s in self.stages
            ],
            "totals": {
                "runtime_seconds": round(self.total_runtime(), 2),
                "findings_count": self.total_findings(),
                "error_count": len(self.total_errors()),
                "token_usage": self.total_token_usage(),
            },
        }

    def to_markdown(self) -> str:
        data = self.to_dict()
        lines: list[str] = ["# Benchmark Report", ""]
        lines.append(f"**Pipeline wall time:** {data['pipeline_total_seconds']:.1f}s")
        lines.append("")

        lines.append("## Per-Stage Stats")
        lines.append("")
        lines.append("| Stage | Runtime | Findings | Errors | Tokens (in/out) |")
        lines.append("|-------|---------|----------|--------|-----------------|")
        for stage in data["stages"]:
            tokens = ""
            if stage["token_usage"]:
                tokens = f"{stage['token_usage'].get('input_tokens', 0):,}/{stage['token_usage'].get('output_tokens', 0):,}"
            lines.append(
                f"| {stage['name']} | {stage['runtime_seconds']:.1f}s "
                f"| {stage['findings_count']} | {len(stage['errors'])} | {tokens} |"
            )
        lines.append("")

        totals = data["totals"]
        lines.append("## Totals")
        lines.append("")
        lines.append(f"- **Runtime:** {totals['runtime_seconds']:.1f}s")
        lines.append(f"- **Findings:** {totals['findings_count']}")
        lines.append(f"- **Errors:** {totals['error_count']}")
        tu = totals["token_usage"]
        if tu:
            lines.append(f"- **Input tokens:** {tu.get('input_tokens', 0):,}")
            lines.append(f"- **Output tokens:** {tu.get('output_tokens', 0):,}")
            lines.append(f"- **Cache write:** {tu.get('cache_creation_input_tokens', 0):,}")
            lines.append(f"- **Cache read:** {tu.get('cache_read_input_tokens', 0):,}")
        lines.append("")
        return "\n".join(lines)

    def finalize(self, output_dir: str) -> None:
        """Write benchmark.json and benchmark.md to the output directory."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        json_path = out / "benchmark.json"
        md_path = out / "benchmark.md"

        json_path.write_text(json.dumps(self.to_dict(), indent=2))
        md_path.write_text(self.to_markdown())
        logger.info("Benchmark report written to %s and %s", json_path, md_path)


def record_stage(
    name: str,
    *,
    findings_count: int = 0,
    errors: list[str] | None = None,
    token_usage: dict[str, int] | None = None,
) -> StageStats:
    """Helper to build a StageStats after timing a stage."""
    return StageStats(
        name=name,
        runtime_seconds=0.0,
        findings_count=findings_count,
        errors=errors or [],
        token_usage=token_usage or {},
    )
