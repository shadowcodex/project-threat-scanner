"""End-to-end tests requiring a real Lima VM.

Run with: pytest -m e2e
These tests are slow (~10 min) and require Lima installed.
"""

from __future__ import annotations

import contextlib
import shutil
import subprocess

import pytest

from thresher.config import ScanConfig, VMConfig
from thresher.vm.lima import LimaError, create_vm, destroy_vm, vm_status

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        shutil.which("limactl") is None,
        reason="limactl not found — install Lima: brew install lima",
    ),
]


@pytest.fixture
def ephemeral_vm():
    """Create and yield an ephemeral VM, then destroy it."""
    config = ScanConfig(
        repo_url="https://github.com/pallets/markupsafe",
        vm=VMConfig(cpus=2, memory=4, disk=20),
        skip_ai=True,
    )
    vm_name = None
    try:
        vm_name = create_vm(config)
        yield vm_name, config
    finally:
        if vm_name:
            with contextlib.suppress(LimaError):
                destroy_vm(vm_name)


class TestVMLifecycle:
    def test_create_destroy(self, ephemeral_vm):
        vm_name, _config = ephemeral_vm
        status = vm_status(vm_name)
        assert status == "Running"

    def test_destroy_removes_vm(self, ephemeral_vm):
        vm_name, _ = ephemeral_vm
        destroy_vm(vm_name)
        status = vm_status(vm_name)
        assert status == "Not found"


class TestDockerInVM:
    def test_docker_available(self, ephemeral_vm):
        vm_name, _ = ephemeral_vm
        result = subprocess.run(
            ["limactl", "shell", vm_name, "docker", "version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"docker not available: {result.stderr}"
