"""Lima VM lifecycle management."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

from thresher.config import ScanConfig

logger = logging.getLogger(__name__)


def _find_data_root() -> Path:
    """Locate the project data root (lima/ directory).

    In a development install the source tree layout has the lima/ directory
    three levels above this file.  In a Homebrew (or other pip-installed)
    layout it lives under ``sys.prefix/share/thresher/``.
    """
    # 1. Development / editable-install layout
    dev_root = Path(__file__).resolve().parents[3]
    if (dev_root / "lima" / "thresher.yaml").exists():
        return dev_root

    # 2. Installed layout (Homebrew virtualenv puts them in share/thresher/)
    installed_root = Path(sys.prefix) / "share" / "thresher"
    if (installed_root / "lima" / "thresher.yaml").exists():
        return installed_root

    # Fall back to dev root so existing error messages stay useful
    return dev_root


_PROJECT_ROOT = _find_data_root()
_TEMPLATE_PATH = _PROJECT_ROOT / "lima" / "thresher.yaml"

# Polling settings
_POLL_INTERVAL = 2  # seconds
_SSH_TIMEOUT = 300  # seconds (first boot can be slow)

# Base VM image name — used by the Lima launcher.
BASE_VM_NAME = "thresher-base"


class LimaError(Exception):
    """Raised when a Lima operation fails."""


def _lima_home() -> Path:
    """Return the Lima home directory (~/.lima by default)."""
    return Path(os.environ.get("LIMA_HOME", Path.home() / ".lima"))


def _read_ha_stderr_log(vm_name: str) -> str:
    """Read the hostagent stderr log for a VM, returning the last 30 lines.

    This log contains the actual error from Virtualization.framework (vz)
    when a VM fails to start. Returns an empty string if the log is missing.
    """
    log_path = _lima_home() / vm_name / "ha.stderr.log"
    try:
        lines = log_path.read_text().splitlines()
        return "\n".join(lines[-30:])
    except (OSError, ValueError):
        return ""


def _check_vz_available() -> bool:
    """Check whether the vz (Virtualization.framework) backend is available."""
    try:
        result = subprocess.run(
            ["limactl", "info"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            info = json.loads(result.stdout)
            return "vz" in info.get("vmTypes", [])
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return False


def _ensure_vz_available() -> None:
    """Raise LimaError with a helpful message if vz is not available."""
    if not _check_vz_available():
        raise LimaError(
            "The vz (Virtualization.framework) backend is not available.\n"
            "Requirements: Apple Silicon Mac running macOS 13 (Ventura) or later.\n"
            "Run 'limactl info' to see supported VM backends."
        )


def _wait_for_ssh(vm_name: str) -> None:
    """Poll until SSH is accepting connections inside the VM."""
    deadline = time.monotonic() + _SSH_TIMEOUT
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(
                ["limactl", "shell", vm_name, "true"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        time.sleep(_POLL_INTERVAL)

    raise LimaError(f"SSH not ready on VM '{vm_name}' after {_SSH_TIMEOUT}s")


def base_exists() -> bool:
    """Check whether the base VM exists."""
    status = vm_status(BASE_VM_NAME)
    return status != "Not found"


def create_vm(config: ScanConfig) -> str:
    """Create and start a new ephemeral Lima VM.

    Returns the VM name.
    """
    _ensure_vz_available()
    vm_name = f"thresher-{int(time.time())}"

    if not _TEMPLATE_PATH.exists():
        raise LimaError(f"Lima template not found: {_TEMPLATE_PATH}")

    create_cmd = [
        "limactl",
        "create",
        "--name", vm_name,
        f"--cpus={config.vm.cpus}",
        f"--memory={config.vm.memory}",
        f"--disk={config.vm.disk}",
        "--plain",
        str(_TEMPLATE_PATH),
    ]

    logger.info("Creating VM %s", vm_name)
    result = _run_limactl(create_cmd, timeout=300)
    if result.returncode != 0:
        raise LimaError(f"Failed to create VM '{vm_name}': {result.stderr}")

    start_vm(vm_name)
    _provision_docker(vm_name)
    return vm_name


def start_vm(vm_name: str) -> None:
    """Start a Lima VM, then wait for SSH to be ready."""
    logger.info("Starting VM %s", vm_name)

    try:
        proc = subprocess.Popen(
            ["limactl", "start", vm_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError as exc:
        raise LimaError("limactl not found. Install Lima: https://lima-vm.io") from exc

    captured_lines: list[str] = []
    for line in proc.stdout:
        stripped = line.rstrip("\n")
        if stripped:
            logger.info("  %s", stripped)
            captured_lines.append(stripped)

    proc.wait()
    if proc.returncode != 0:
        diag_parts = [f"Failed to start VM '{vm_name}' (exit {proc.returncode})"]
        tail = captured_lines[-10:]
        if tail:
            diag_parts.append("limactl output:\n  " + "\n  ".join(tail))
        ha_log = _read_ha_stderr_log(vm_name)
        if ha_log:
            diag_parts.append(f"ha.stderr.log:\n  {ha_log}")
        raise LimaError("\n".join(diag_parts))

    logger.info("VM %s started, waiting for SSH...", vm_name)
    _wait_for_ssh(vm_name)
    logger.info("VM %s is ready", vm_name)


def stop_vm(vm_name: str) -> None:
    """Stop a Lima VM without deleting it."""
    logger.info("Stopping VM %s", vm_name)
    # Best-effort sync before stop
    try:
        subprocess.run(
            ["limactl", "shell", vm_name, "sync"],
            capture_output=True, timeout=30,
        )
    except Exception:
        pass
    result = _run_limactl(["limactl", "stop", vm_name], timeout=120)
    if result.returncode != 0:
        raise LimaError(f"Failed to stop VM '{vm_name}': {result.stderr}")


def destroy_vm(vm_name: str) -> None:
    """Force-delete a Lima VM."""
    cmd = ["limactl", "delete", "-f", vm_name]
    result = _run_limactl(cmd, timeout=120)
    if result.returncode != 0:
        raise LimaError(f"Failed to destroy VM '{vm_name}': {result.stderr}")


def ensure_base_running() -> str:
    """Start the base VM if it is stopped and return its name.

    Raises:
        LimaError: If the base VM does not exist or cannot be started.
    """
    status = vm_status(BASE_VM_NAME)
    if status == "Not found":
        raise LimaError(
            f"Base VM '{BASE_VM_NAME}' not found. "
            "Run `thresher build` first to create the cached base image."
        )
    if status != "Running":
        start_vm(BASE_VM_NAME)
    return BASE_VM_NAME


def load_image(vm_name: str, image_path: str) -> None:
    """Load a Docker image tarball into the VM.

    Args:
        vm_name: Running Lima VM name.
        image_path: Host path to the .tar image file.
    """
    # Copy the image into the VM then load it
    remote_path = "/tmp/thresher-image.tar"
    result = subprocess.run(
        ["limactl", "copy", image_path, f"{vm_name}:{remote_path}"],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        raise LimaError(f"Failed to copy image to VM: {result.stderr}")

    result = subprocess.run(
        ["limactl", "shell", vm_name, "docker", "load", "-i", remote_path],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        raise LimaError(f"Failed to load Docker image: {result.stderr}")


def vm_status(vm_name: str) -> str:
    """Get the status of a Lima VM.

    Returns:
        Status string (e.g., "Running", "Stopped", or "Not found").
    """
    cmd = ["limactl", "list", "--format", "{{.Status}}", vm_name]
    result = _run_limactl(cmd, timeout=30)

    if result.returncode != 0:
        if "not found" in result.stderr.lower() or not result.stdout.strip():
            return "Not found"
        raise LimaError(f"Failed to get status of VM '{vm_name}': {result.stderr}")

    return result.stdout.strip()


def _provision_docker(vm_name: str) -> None:
    """Install Docker in the VM (minimal — tools live in the container)."""
    cmds = [
        # Install Docker
        "curl -fsSL https://get.docker.com | sudo sh",
        # Add current user to docker group
        "sudo usermod -aG docker $(whoami)",
    ]
    for cmd in cmds:
        result = subprocess.run(
            ["limactl", "shell", vm_name, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            raise LimaError(f"Docker provisioning failed: {result.stderr}")
    logger.info("Docker provisioned in VM %s", vm_name)


def _run_limactl(
    cmd: list[str], timeout: int = 120
) -> subprocess.CompletedProcess[str]:
    """Run a limactl command synchronously."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise LimaError(
            "limactl not found. Install Lima: https://lima-vm.io"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise LimaError(
            f"limactl command timed out after {timeout}s: {' '.join(cmd)}"
        ) from exc
