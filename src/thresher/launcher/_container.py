"""Shared docker run argv builder for the hardened Thresher container.

Both the Docker and Lima launch modes drop the harness into the same
hardened container — read-only root, every capability dropped,
no-new-privileges, an unprivileged ``thresher`` user, and tmpfs mounts
sized for each writable path. The only differences between modes are
where the host output and config live and how credentials are
forwarded.

This module owns the security baseline so the two launchers can't
silently drift on the flags that define the sandbox. Add a flag here
once and both modes get it.
"""

from __future__ import annotations

DOCKER_IMAGE = "thresher:latest"

# Tmpfs mounts for every writable path inside the read-only container.
# Sizes match historical empirical limits — bumping any of these is a
# real decision and should be reviewed in code review.
_TMPFS_MOUNTS = [
    "/tmp:rw,noexec,nosuid,size=1073741824,uid=1000,gid=1000",
    "/home/thresher:rw,size=536870912,uid=1000,gid=1000",
    "/opt/target:rw,size=2147483648,uid=1000,gid=1000",
    "/opt/scan-results:rw,size=1073741824,uid=1000,gid=1000",
    "/opt/deps:rw,size=2147483648,uid=1000,gid=1000",
]

# Vuln-DB env vars: point Grype/Trivy at the pre-populated DBs baked
# into the image and skip runtime updates. Concurrent DB downloads
# blow out the /home tmpfs, so this is load-bearing.
_VULN_DB_ENV = [
    "-e", "GRYPE_DB_CACHE_DIR=/opt/vuln-db/grype",
    "-e", "GRYPE_DB_AUTO_UPDATE=false",
    "-e", "TRIVY_CACHE_DIR=/opt/vuln-db/trivy",
    "-e", "TRIVY_SKIP_DB_UPDATE=true",
]


def build_docker_args(
    *,
    output_mount: str,
    config_mount: str,
    env_flags: list[str],
) -> list[str]:
    """Return the ``docker run`` argv for the hardened Thresher container.

    Args:
        output_mount: Host→container bind mount for the output dir, in
            ``-v`` form. Docker mode passes a host-resolved path; Lima
            mode passes the in-VM path ``/opt/reports:/output``.
        config_mount: Host→container bind mount for the config JSON, in
            ``-v`` form (always read-only).
        env_flags: Pre-built ``["-e", "KEY=value"]`` or ``["-e", "KEY"]``
            entries for credentials. Docker mode passes by value; Lima
            mode forwards by name through limactl shell.

    Returns:
        The full argv list to hand to ``subprocess.run``.
    """
    args: list[str] = [
        "docker", "run",
        "-v", output_mount,
        "-v", config_mount,
        *env_flags,
        *_VULN_DB_ENV,
        "--rm", "--read-only",
    ]
    for mount in _TMPFS_MOUNTS:
        args += ["--tmpfs", mount]
    args += [
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user", "thresher",
        DOCKER_IMAGE,
        "--config", "/config/config.json",
        "--output", "/output",
    ]
    return args
