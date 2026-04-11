"""Report Synthesis agent — merges scanner and AI findings into final reports.

Invokes Claude Code headless to produce executive-summary.md,
detailed-report.md, and synthesis-findings.md from enriched findings.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml

from thresher.config import ScanConfig
from thresher.run import run as run_cmd

logger = logging.getLogger(__name__)

_DEFINITION_PATH = Path(__file__).parent / "definitions" / "report" / "synthesize.yaml"


def _load_definition() -> dict[str, Any]:
    """Load the synthesize YAML definition."""
    with open(_DEFINITION_PATH) as f:
        return yaml.safe_load(f)


def _write_file(path: str, content: str) -> None:
    """Write content to a local file."""
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _build_synthesis_prompt(
    definition: dict[str, Any], report_dir: str, input_path: str,
) -> str:
    """Format the YAML prompt template with runtime paths."""
    return definition["prompt"].format(
        report_dir=report_dir,
        input_path=input_path,
    )


def run_synthesize_agent(
    config: ScanConfig,
    report_dir: str,
    synthesis_input: str,
) -> bool:
    """Run the synthesis agent to generate report markdown files.

    Writes the synthesis input to the report directory, builds the prompt,
    and invokes Claude Code headless to generate the report files.

    Args:
        config: Scan configuration.
        report_dir: Directory where report files will be written.
        synthesis_input: Markdown-formatted synthesis input text.

    Returns:
        True if the agent produced the expected output files.
    """
    definition = _load_definition()
    tools = ",".join(definition["tools"])
    max_turns = getattr(config, "synthesize_max_turns", None) or definition["max_turns"]

    # Write synthesis input to report directory
    input_path = f"{report_dir}/synthesis_input.md"
    _write_file(input_path, synthesis_input)

    # Build and write prompt from YAML definition template
    synthesis_prompt = _build_synthesis_prompt(definition, report_dir, input_path)
    prompt_path = Path(tempfile.mktemp(suffix="_synthesis_prompt.txt"))

    try:
        prompt_path.write_text(synthesis_prompt)

        model = config.model
        cmd = [
            "claude",
            "-p", str(prompt_path),
            "--model", model,
            "--allowedTools", tools,
            "--output-format", "stream-json",
            "--verbose",
            "--max-turns", str(max_turns),
        ]

        env = os.environ.copy()
        ai_env = config.ai_env()
        env.update(ai_env)

        logger.info("Invoking synthesis agent (max_turns=%d)", max_turns)
        try:
            result = run_cmd(
                cmd,
                label="synthesize",
                cwd=report_dir,
                env=env,
                timeout=1800,
            )
            exit_code = result.returncode
        except Exception as exc:
            logger.warning("Synthesis agent failed: %s", exc)
            exit_code = 1

        logger.info("Synthesis agent completed: exit_code=%d", exit_code)

        # Verify expected output files exist
        agent_succeeded = (
            os.path.isfile(f"{report_dir}/executive-summary.md")
            and os.path.isfile(f"{report_dir}/detailed-report.md")
        )

        if agent_succeeded:
            logger.info("Synthesis agent produced expected report files")
        else:
            logger.warning("Synthesis agent did not produce expected files")

        return agent_succeeded

    finally:
        try:
            prompt_path.unlink(missing_ok=True)
        except Exception:
            pass
