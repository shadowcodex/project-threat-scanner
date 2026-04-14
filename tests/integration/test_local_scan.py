"""Integration tests for local path scanning."""

import os
import subprocess
from pathlib import Path

from thresher.config import ScanConfig


class TestLocalCopyPlainDir:
    def test_copytree_copies_all_files(self, tmp_path):
        """Non-git local directory is copied faithfully via copy_local_source."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "main.py").write_text("print('hello')")
        (source / "sub").mkdir()
        (source / "sub" / "lib.py").write_text("x = 1")
        (source / ".env").write_text("SECRET=yes")

        target = tmp_path / "target"
        target.mkdir()

        from thresher.harness.pipeline import copy_local_source

        result = copy_local_source(str(source), str(target))

        assert result == str(target)
        assert (target / "main.py").read_text() == "print('hello')"
        assert (target / "sub" / "lib.py").read_text() == "x = 1"
        assert (target / ".env").read_text() == "SECRET=yes"


class TestLocalCopyGitRepo:
    def test_git_repo_clones_via_safe_clone(self, tmp_path):
        """Local git repo is cloned using safe_clone with file:// URL."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "main.py").write_text("print('hello')")

        git_env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "test",
            "GIT_AUTHOR_EMAIL": "test@test.com",
            "GIT_COMMITTER_NAME": "test",
            "GIT_COMMITTER_EMAIL": "test@test.com",
        }
        subprocess.run(["git", "init"], cwd=str(source), capture_output=True, check=True)
        subprocess.run(["git", "add", "."], cwd=str(source), capture_output=True, check=True)
        subprocess.run(
            ["git", "commit", "-m", "init"],
            cwd=str(source), capture_output=True, check=True, env=git_env,
        )

        target = str(tmp_path / "target")

        from thresher.harness.clone import safe_clone

        result = safe_clone(f"file://{source}", target)

        assert result == target
        assert (Path(target) / "main.py").read_text() == "print('hello')"
