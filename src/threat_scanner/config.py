"""Configuration management for threat-scanner."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "threat-scanner" / "config.yaml"


@dataclass
class VMConfig:
    cpus: int = 4
    memory: int = 8  # GB
    disk: int = 50  # GB


@dataclass
class ScanConfig:
    repo_url: str = ""
    depth: int = 2
    skip_ai: bool = False
    verbose: bool = False
    output_dir: str = "./scan-results"
    vm: VMConfig = field(default_factory=VMConfig)
    anthropic_api_key: str = ""
    model: str = "sonnet"

    def validate(self) -> list[str]:
        errors = []
        if not self.repo_url:
            errors.append("repo_url is required")
        if not self.skip_ai and not self.anthropic_api_key:
            errors.append(
                "ANTHROPIC_API_KEY env var required (or use --skip-ai for deterministic-only scan)"
            )
        if self.depth < 1:
            errors.append("depth must be >= 1")
        return errors


def load_config(
    repo_url: str,
    depth: int | None = None,
    skip_ai: bool = False,
    verbose: bool = False,
    output_dir: str | None = None,
    cpus: int | None = None,
    memory: int | None = None,
    disk: int | None = None,
    config_path: Path | None = None,
) -> ScanConfig:
    """Build ScanConfig from config file + CLI args + env vars. CLI args take precedence."""
    config = ScanConfig()

    # Load config file if it exists
    path = config_path or DEFAULT_CONFIG_PATH
    if path.exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        if "default_depth" in data:
            config.depth = data["default_depth"]
        if "model" in data:
            config.model = data["model"]
        vm_data = data.get("vm", {})
        if "cpus" in vm_data:
            config.vm.cpus = vm_data["cpus"]
        if "memory" in vm_data:
            config.vm.memory = vm_data["memory"]
        if "disk" in vm_data:
            config.vm.disk = vm_data["disk"]

    # CLI args override config file
    config.repo_url = repo_url
    if depth is not None:
        config.depth = depth
    config.skip_ai = skip_ai
    config.verbose = verbose
    if output_dir is not None:
        config.output_dir = output_dir
    if cpus is not None:
        config.vm.cpus = cpus
    if memory is not None:
        config.vm.memory = memory
    if disk is not None:
        config.vm.disk = disk

    # API key from env
    config.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    return config
