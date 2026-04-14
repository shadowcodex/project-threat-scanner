"""Unit tests for Lima VM lifecycle."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from thresher.config import ScanConfig, VMConfig
from thresher.vm.lima import (
    BASE_VM_NAME,
    LimaError,
    _check_vz_available,
    _read_ha_stderr_log,
    base_exists,
    ensure_base_running,
    start_vm,
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


class TestStopVm:
    @patch("thresher.vm.lima.subprocess.run")
    @patch("thresher.vm.lima._run_limactl")
    def test_graceful_stop_syncs_first(self, mock_run, mock_proc):
        mock_run.return_value = MagicMock(returncode=0)
        mock_proc.return_value = MagicMock(returncode=0)
        stop_vm("test-vm")
        # Verify limactl stop was called
        mock_run.assert_called_once_with(["limactl", "stop", "test-vm"], timeout=120)

    @patch("thresher.vm.lima.subprocess.run")
    @patch("thresher.vm.lima._run_limactl")
    def test_raises_on_failure(self, mock_run, mock_proc):
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        mock_proc.return_value = MagicMock(returncode=0)
        with pytest.raises(LimaError, match="Failed to stop"):
            stop_vm("test-vm")


class TestReadHaStderrLog:
    def test_reads_last_lines(self, tmp_path):
        log_file = tmp_path / "test-vm" / "ha.stderr.log"
        log_file.parent.mkdir(parents=True)
        log_file.write_text("line1\nline2\nline3\n")
        with patch("thresher.vm.lima._lima_home", return_value=tmp_path):
            result = _read_ha_stderr_log("test-vm")
        assert "line1" in result
        assert "line3" in result

    def test_returns_empty_when_missing(self, tmp_path):
        with patch("thresher.vm.lima._lima_home", return_value=tmp_path):
            result = _read_ha_stderr_log("nonexistent-vm")
        assert result == ""


class TestCheckVzAvailable:
    @patch("thresher.vm.lima.subprocess.run")
    def test_returns_true_when_vz_listed(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"vmTypes": ["qemu", "vz"]}',
        )
        assert _check_vz_available() is True

    @patch("thresher.vm.lima.subprocess.run")
    def test_returns_false_when_vz_not_listed(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"vmTypes": ["qemu"]}',
        )
        assert _check_vz_available() is False

    @patch("thresher.vm.lima.subprocess.run", side_effect=FileNotFoundError)
    def test_returns_false_when_limactl_missing(self, mock_run):
        assert _check_vz_available() is False


class TestStartVmDiagnostics:
    @patch("thresher.vm.lima._read_ha_stderr_log", return_value="vz error: entitlement missing")
    @patch("thresher.vm.lima.subprocess.Popen")
    def test_includes_ha_log_on_failure(self, mock_popen, mock_log):
        proc = MagicMock()
        proc.stdout = iter(['level=fatal msg="exiting"\n'])
        proc.wait.return_value = None
        proc.returncode = 1
        mock_popen.return_value = proc

        with pytest.raises(LimaError, match=r"ha\.stderr\.log"):
            start_vm("test-vm")

    @patch("thresher.vm.lima._read_ha_stderr_log", return_value="")
    @patch("thresher.vm.lima.subprocess.Popen")
    def test_includes_limactl_output_on_failure(self, mock_popen, mock_log):
        proc = MagicMock()
        proc.stdout = iter(["fatal: something broke\n"])
        proc.wait.return_value = None
        proc.returncode = 1
        mock_popen.return_value = proc

        with pytest.raises(LimaError, match="something broke"):
            start_vm("test-vm")
