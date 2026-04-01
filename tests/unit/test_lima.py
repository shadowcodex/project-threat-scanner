"""Unit tests for Lima VM lifecycle, including base VM caching."""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from thresher.config import ScanConfig, VMConfig
from thresher.vm.lima import (
    BASE_VM_NAME,
    LimaError,
    base_exists,
    build_base,
    clean_working_dirs,
    ensure_base_running,
    stop_vm,
)


@pytest.fixture
def config():
    return ScanConfig(
        repo_url="",
        skip_ai=True,
        vm=VMConfig(cpus=4, memory=8, disk=50),
    )


class TestBaseExists:
    @patch("thresher.vm.lima.vm_status", return_value="Stopped")
    def test_returns_true_when_stopped(self, mock_status):
        assert base_exists() is True
        mock_status.assert_called_once_with(BASE_VM_NAME)

    @patch("thresher.vm.lima.vm_status", return_value="Running")
    def test_returns_true_when_running(self, mock_status):
        assert base_exists() is True

    @patch("thresher.vm.lima.vm_status", return_value="Not found")
    def test_returns_false_when_not_found(self, mock_status):
        assert base_exists() is False


class TestEnsureBaseRunning:
    @patch("thresher.vm.lima.start_vm")
    @patch("thresher.vm.lima.vm_status", return_value="Stopped")
    def test_starts_stopped_vm(self, mock_status, mock_start):
        name = ensure_base_running()
        assert name == BASE_VM_NAME
        mock_start.assert_called_once_with(BASE_VM_NAME)

    @patch("thresher.vm.lima.start_vm")
    @patch("thresher.vm.lima.vm_status", return_value="Running")
    def test_skips_start_if_running(self, mock_status, mock_start):
        name = ensure_base_running()
        assert name == BASE_VM_NAME
        mock_start.assert_not_called()

    @patch("thresher.vm.lima.vm_status", return_value="Not found")
    def test_raises_when_not_found(self, mock_status):
        with pytest.raises(LimaError, match="not found"):
            ensure_base_running()


class TestBuildBase:
    @patch("thresher.vm.lima.stop_vm")
    @patch("thresher.vm.lima.provision_vm")
    @patch("thresher.vm.lima.start_vm")
    @patch("thresher.vm.lima._run_limactl")
    @patch("thresher.vm.lima._TEMPLATE_PATH")
    @patch("thresher.vm.lima.base_exists", return_value=False)
    def test_builds_fresh_base(
        self, mock_exists, mock_tpl, mock_run, mock_start, mock_prov, mock_stop, config
    ):
        mock_tpl.exists.return_value = True
        mock_tpl.__str__ = lambda s: "/fake/thresher.yaml"
        mock_run.return_value = MagicMock(returncode=0)

        build_base(config)

        # Should create, start, provision, stop
        mock_run.assert_called_once()
        mock_start.assert_called_once_with(BASE_VM_NAME)
        mock_prov.assert_called_once_with(BASE_VM_NAME, config)
        mock_stop.assert_called_once_with(BASE_VM_NAME)

    @patch("thresher.vm.lima.stop_vm")
    @patch("thresher.vm.lima.provision_vm")
    @patch("thresher.vm.lima.start_vm")
    @patch("thresher.vm.lima._run_limactl")
    @patch("thresher.vm.lima._TEMPLATE_PATH")
    @patch("thresher.vm.lima.destroy_vm")
    @patch("thresher.vm.lima.base_exists", return_value=True)
    def test_destroys_existing_before_rebuild(
        self, mock_exists, mock_destroy, mock_tpl, mock_run,
        mock_start, mock_prov, mock_stop, config
    ):
        mock_tpl.exists.return_value = True
        mock_tpl.__str__ = lambda s: "/fake/thresher.yaml"
        mock_run.return_value = MagicMock(returncode=0)

        build_base(config)

        mock_destroy.assert_called_once_with(BASE_VM_NAME)


class TestCleanWorkingDirs:
    @patch("thresher.vm.lima.ssh_exec", return_value=("", "", 0))
    def test_cleans_all_dirs(self, mock_ssh):
        clean_working_dirs("test-vm")
        assert mock_ssh.call_count == 4
        # Verify each working dir is cleaned
        cmds = [c[0][1] for c in mock_ssh.call_args_list]
        assert any("/opt/target" in cmd for cmd in cmds)
        assert any("/opt/deps" in cmd for cmd in cmds)
        assert any("/opt/scan-results" in cmd for cmd in cmds)
        assert any("/opt/security-reports" in cmd for cmd in cmds)


class TestStopVm:
    @patch("thresher.vm.lima._run_limactl")
    def test_stops_vm(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        stop_vm("test-vm")
        mock_run.assert_called_once_with(["limactl", "stop", "test-vm"], timeout=120)

    @patch("thresher.vm.lima._run_limactl")
    def test_raises_on_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        with pytest.raises(LimaError, match="Failed to stop"):
            stop_vm("test-vm")
