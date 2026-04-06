"""Unit tests for thresher.harness.deps."""

import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from thresher.harness.deps import (
    detect_ecosystems,
    download_python,
    download_node,
    download_rust,
    download_go,
    resolve_deps,
    build_manifest,
)


class TestDetectEcosystems:
    def test_detects_python_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==2.0\n")
        assert "python" in detect_ecosystems(str(tmp_path))

    def test_detects_python_pyproject(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        assert "python" in detect_ecosystems(str(tmp_path))

    def test_detects_python_setup_py(self, tmp_path):
        (tmp_path / "setup.py").write_text("from setuptools import setup\n")
        assert "python" in detect_ecosystems(str(tmp_path))

    def test_detects_python_pipfile(self, tmp_path):
        (tmp_path / "Pipfile").write_text("[packages]\n")
        assert "python" in detect_ecosystems(str(tmp_path))

    def test_detects_node(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "test"}\n')
        assert "node" in detect_ecosystems(str(tmp_path))

    def test_detects_rust(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text("[package]\n")
        assert "rust" in detect_ecosystems(str(tmp_path))

    def test_detects_go(self, tmp_path):
        (tmp_path / "go.mod").write_text("module example.com/test\n")
        assert "go" in detect_ecosystems(str(tmp_path))

    def test_detects_multiple(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask\n")
        (tmp_path / "package.json").write_text("{}\n")
        eco = detect_ecosystems(str(tmp_path))
        assert "python" in eco and "node" in eco

    def test_no_ecosystems(self, tmp_path):
        assert detect_ecosystems(str(tmp_path)) == []


class TestDownloadPython:
    @patch("thresher.harness.deps.subprocess.run")
    def test_calls_pip_download_no_binary(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        src = tmp_path / "src"
        src.mkdir()
        (src / "requirements.txt").write_text("flask==2.0\n")
        deps = tmp_path / "deps"
        deps.mkdir()
        download_python(str(src), str(deps))
        args = mock_run.call_args[0][0]
        assert "--no-binary" in args
        assert ":all:" in args

    @patch("thresher.harness.deps.subprocess.run")
    def test_calls_pip_download_with_pyproject(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        src = tmp_path / "src"
        src.mkdir()
        (src / "pyproject.toml").write_text("[project]\nname = 'test'\n")
        deps = tmp_path / "deps"
        deps.mkdir()
        download_python(str(src), str(deps))
        args = mock_run.call_args[0][0]
        assert "pip3" in args
        assert "--no-binary" in args

    @patch("thresher.harness.deps.subprocess.run")
    def test_no_call_when_no_manifest(self, mock_run, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        deps = tmp_path / "deps"
        deps.mkdir()
        download_python(str(src), str(deps))
        mock_run.assert_not_called()

    @patch("thresher.harness.deps.subprocess.run")
    def test_pipfile_extraction(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        src = tmp_path / "src"
        src.mkdir()
        (src / "Pipfile").write_text('[packages]\nflask = "*"\nrequests = ">=2.0"\n')
        deps = tmp_path / "deps"
        deps.mkdir()
        download_python(str(src), str(deps))
        args = mock_run.call_args[0][0]
        assert "-r" in args


class TestDownloadNode:
    @patch("thresher.harness.deps.subprocess.run")
    def test_calls_npm_pack(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout=b"")
        src = tmp_path / "src"
        src.mkdir()
        (src / "package.json").write_text(
            json.dumps({"dependencies": {"express": "4.18.0"}})
        )
        deps = tmp_path / "deps"
        deps.mkdir()
        download_node(str(src), str(deps))
        npm_calls = [c for c in mock_run.call_args_list if "npm" in str(c)]
        assert len(npm_calls) > 0

    @patch("thresher.harness.deps.subprocess.run")
    def test_no_call_when_no_package_json(self, mock_run, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        deps = tmp_path / "deps"
        deps.mkdir()
        download_node(str(src), str(deps))
        mock_run.assert_not_called()

    @patch("thresher.harness.deps.subprocess.run")
    def test_packs_dev_dependencies(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout=b"")
        src = tmp_path / "src"
        src.mkdir()
        (src / "package.json").write_text(
            json.dumps({"devDependencies": {"jest": "29.0.0"}})
        )
        deps = tmp_path / "deps"
        deps.mkdir()
        download_node(str(src), str(deps))
        npm_calls = [c for c in mock_run.call_args_list if "npm" in str(c)]
        assert len(npm_calls) > 0


class TestDownloadRust:
    @patch("thresher.harness.deps.subprocess.run")
    def test_calls_cargo_vendor(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        src = tmp_path / "src"
        src.mkdir()
        (src / "Cargo.toml").write_text("[package]\nname = 'test'\n")
        deps = tmp_path / "deps"
        deps.mkdir()
        download_rust(str(src), str(deps))
        args = mock_run.call_args[0][0]
        assert "cargo" in args and "vendor" in args

    @patch("thresher.harness.deps.subprocess.run")
    def test_no_call_when_no_cargo_toml(self, mock_run, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        deps = tmp_path / "deps"
        deps.mkdir()
        download_rust(str(src), str(deps))
        mock_run.assert_not_called()


class TestDownloadGo:
    @patch("thresher.harness.deps.subprocess.run")
    def test_calls_go_mod_vendor(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        src = tmp_path / "src"
        src.mkdir()
        (src / "go.mod").write_text("module example.com/test\ngo 1.21\n")
        deps = tmp_path / "deps"
        deps.mkdir()
        download_go(str(src), str(deps))
        args = mock_run.call_args[0][0]
        assert "go" in args

    @patch("thresher.harness.deps.subprocess.run")
    def test_no_call_when_no_go_mod(self, mock_run, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        deps = tmp_path / "deps"
        deps.mkdir()
        download_go(str(src), str(deps))
        mock_run.assert_not_called()


class TestBuildManifest:
    def test_writes_manifest_json(self, tmp_path):
        py_dir = tmp_path / "python"
        py_dir.mkdir()
        (py_dir / "flask-2.0.tar.gz").write_text("fake")
        build_manifest(str(tmp_path))
        manifest = tmp_path / "dep_manifest.json"
        assert manifest.exists()
        data = json.loads(manifest.read_text())
        assert "python" in data

    def test_manifest_contains_package_info(self, tmp_path):
        py_dir = tmp_path / "python"
        py_dir.mkdir()
        (py_dir / "requests-2.28.0.tar.gz").write_text("fake")
        build_manifest(str(tmp_path))
        data = json.loads((tmp_path / "dep_manifest.json").read_text())
        pkgs = data["python"]
        assert any(p["name"] == "requests" for p in pkgs)

    def test_skips_temp_files(self, tmp_path):
        py_dir = tmp_path / "python"
        py_dir.mkdir()
        (py_dir / "_pipfile_reqs.txt").write_text("flask\n")
        (py_dir / "flask-2.0.tar.gz").write_text("fake")
        build_manifest(str(tmp_path))
        data = json.loads((tmp_path / "dep_manifest.json").read_text())
        names = [p["name"] for p in data.get("python", [])]
        assert "_pipfile_reqs.txt" not in names

    def test_skips_non_ecosystem_dirs(self, tmp_path):
        (tmp_path / "hidden").mkdir()
        (tmp_path / "python").mkdir()
        (tmp_path / "python" / "pkg-1.0.tar.gz").write_text("x")
        build_manifest(str(tmp_path))
        data = json.loads((tmp_path / "dep_manifest.json").read_text())
        assert "hidden" not in data
        assert "python" in data

    def test_empty_deps_dir(self, tmp_path):
        build_manifest(str(tmp_path))
        manifest = tmp_path / "dep_manifest.json"
        assert manifest.exists()

    def test_node_packages(self, tmp_path):
        node_dir = tmp_path / "node"
        node_dir.mkdir()
        (node_dir / "express-4.18.0.tgz").write_text("fake")
        build_manifest(str(tmp_path))
        data = json.loads((tmp_path / "dep_manifest.json").read_text())
        assert "node" in data


class TestResolveDeps:
    @patch("thresher.harness.deps.download_python")
    @patch("thresher.harness.deps.download_node")
    @patch("thresher.harness.deps.build_manifest")
    def test_calls_downloaders_for_detected_ecosystems(
        self, mock_manifest, mock_node, mock_python, tmp_path
    ):
        deps_dir = str(tmp_path / "deps")
        resolve_deps(
            target_dir="/opt/target",
            ecosystems=["python", "node"],
            hidden_deps={},
            config={"depth": 2, "high_risk_dep": False},
            deps_dir=deps_dir,
        )
        mock_python.assert_called_once()
        mock_node.assert_called_once()
        mock_manifest.assert_called_once()

    @patch("thresher.harness.deps.download_python")
    @patch("thresher.harness.deps.build_manifest")
    def test_returns_deps_dir(self, mock_manifest, mock_python, tmp_path):
        deps_dir = str(tmp_path / "deps")
        result = resolve_deps(
            target_dir="/opt/target",
            ecosystems=["python"],
            hidden_deps={},
            config={},
            deps_dir=deps_dir,
        )
        assert result == deps_dir

    @patch("thresher.harness.deps.download_hidden")
    @patch("thresher.harness.deps.build_manifest")
    def test_calls_download_hidden_when_provided(
        self, mock_manifest, mock_hidden, tmp_path
    ):
        deps_dir = str(tmp_path / "deps")
        hidden = {"hidden_dependencies": [{"type": "git", "source": "https://github.com/x/y", "confidence": "high", "risk": "low"}]}
        resolve_deps(
            target_dir="/opt/target",
            ecosystems=[],
            hidden_deps=hidden,
            config={"high_risk_dep": False},
            deps_dir=deps_dir,
        )
        mock_hidden.assert_called_once()

    @patch("thresher.harness.deps.build_manifest")
    def test_skips_unknown_ecosystems(self, mock_manifest, tmp_path):
        deps_dir = str(tmp_path / "deps")
        # Should not raise
        resolve_deps(
            target_dir="/opt/target",
            ecosystems=["unknown_eco"],
            hidden_deps={},
            config={},
            deps_dir=deps_dir,
        )
        mock_manifest.assert_called_once()
