"""Tests for thresher.launcher._container — shared docker argv builder."""

from __future__ import annotations

from thresher.launcher._container import DOCKER_IMAGE, build_docker_args


class TestBuildDockerArgs:
    def _args(self, **kwargs):
        return build_docker_args(
            output_mount=kwargs.get("output_mount", "/host/out:/output"),
            config_mount=kwargs.get(
                "config_mount",
                "/host/cfg.json:/config/config.json:ro",
            ),
            env_flags=kwargs.get("env_flags", []),
        )

    def test_starts_with_docker_run(self):
        args = self._args()
        assert args[0:2] == ["docker", "run"]

    def test_includes_output_and_config_mounts(self):
        args = self._args(
            output_mount="/abs/out:/output",
            config_mount="/abs/cfg.json:/config/config.json:ro",
        )
        assert "-v" in args
        assert "/abs/out:/output" in args
        assert "/abs/cfg.json:/config/config.json:ro" in args

    def test_inserts_caller_env_flags(self):
        args = self._args(env_flags=["-e", "ANTHROPIC_API_KEY=sk-test"])
        assert "ANTHROPIC_API_KEY=sk-test" in args

    def test_locks_down_capabilities(self):
        args = self._args()
        assert "--cap-drop=ALL" in args
        assert "--security-opt=no-new-privileges" in args

    def test_runs_as_thresher_user(self):
        args = self._args()
        idx = args.index("--user")
        assert args[idx + 1] == "thresher"

    def test_filesystem_is_read_only(self):
        assert "--read-only" in self._args()

    def test_container_is_removed_after_exit(self):
        assert "--rm" in self._args()

    def test_required_tmpfs_mounts_present(self):
        args = self._args()
        tmpfs_targets = [
            arg
            for arg in args
            if isinstance(arg, str)
            and arg.startswith(("/tmp:", "/home/thresher:", "/opt/target:", "/opt/scan-results:", "/opt/deps:"))
        ]
        assert len(tmpfs_targets) == 5
        for t in tmpfs_targets:
            assert "uid=1000" in t and "gid=1000" in t

    def test_vuln_db_env_vars_present(self):
        args = self._args()
        assert "GRYPE_DB_CACHE_DIR=/opt/vuln-db/grype" in args
        assert "GRYPE_DB_AUTO_UPDATE=false" in args
        assert "TRIVY_CACHE_DIR=/opt/vuln-db/trivy" in args
        assert "TRIVY_SKIP_DB_UPDATE=true" in args

    def test_image_is_thresher_latest(self):
        args = self._args()
        assert DOCKER_IMAGE in args

    def test_image_followed_by_harness_args(self):
        args = self._args()
        idx = args.index(DOCKER_IMAGE)
        tail = args[idx + 1 :]
        assert tail == ["--config", "/config/config.json", "--output", "/output"]

    def test_env_flags_appear_before_image(self):
        args = self._args(env_flags=["-e", "ANTHROPIC_API_KEY=k"])
        assert args.index("ANTHROPIC_API_KEY=k") < args.index(DOCKER_IMAGE)

    def test_source_mount_adds_volume(self):
        args = build_docker_args(
            output_mount="/host/out:/output",
            config_mount="/host/cfg.json:/config/config.json:ro",
            env_flags=[],
            source_mount="/local/src:/opt/source:ro",
        )
        v_indices = [i for i, a in enumerate(args) if a == "-v"]
        source_mounts = [args[i + 1] for i in v_indices if args[i + 1].startswith("/local/src")]
        assert len(source_mounts) == 1
        assert source_mounts[0] == "/local/src:/opt/source:ro"

    def test_no_source_mount_by_default(self):
        args = build_docker_args(
            output_mount="/host/out:/output",
            config_mount="/host/cfg.json:/config/config.json:ro",
            env_flags=[],
        )
        v_indices = [i for i, a in enumerate(args) if a == "-v"]
        source_mounts = [args[i + 1] for i in v_indices if "/opt/source" in args[i + 1]]
        assert len(source_mounts) == 0

    def test_supports_env_var_forwarding_form(self):
        """Lima mode passes -e NAME (no value) to forward host env var."""
        args = self._args(env_flags=["-e", "ANTHROPIC_API_KEY", "-e", "CLAUDE_CODE_OAUTH_TOKEN"])
        assert "ANTHROPIC_API_KEY" in args
        assert "CLAUDE_CODE_OAUTH_TOKEN" in args
