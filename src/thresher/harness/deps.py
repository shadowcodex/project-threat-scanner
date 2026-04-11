"""deps.py — Python port of dependency resolution shell scripts.

Replaces: detect.sh, download_*.sh, run.sh, manifest.sh, build_manifest.py
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import tomllib
from pathlib import Path

from thresher.run import retry
from thresher.run import run as run_cmd

log = logging.getLogger(__name__)


# ── Status accumulator (Task 7: surface dep resolution failures) ──────────────


class DepResolutionStatus:
    """Tracks per-ecosystem download status so the report pipeline can
    surface dependency-resolution failures rather than silently degrading
    downstream scanner coverage."""

    def __init__(self) -> None:
        self._ecosystems: dict[str, dict[str, str]] = {}

    def record(self, ecosystem: str, status: str, reason: str = "") -> None:
        self._ecosystems[ecosystem] = {"status": status, "reason": reason}

    def to_dict(self) -> dict:
        return {"ecosystems": dict(self._ecosystems)}

    def write(self, deps_dir: Path) -> Path:
        path = deps_dir / "dep_resolution.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))
        return path

    @property
    def has_failures(self) -> bool:
        return any(entry.get("status") == "failed" for entry in self._ecosystems.values())


# Module-level current status — set by resolve_deps so download_python /
# download_node etc. can record their outcome without threading the object
# through every call site. None outside a resolve_deps call.
_current_status: DepResolutionStatus | None = None


def _record_status(ecosystem: str, status: str, reason: str = "") -> None:
    if _current_status is not None:
        _current_status.record(ecosystem, status, reason)


# ── Ecosystem Detection ────────────────────────────────────────────────────────

#: Maps ecosystem name to the indicator files that signal its presence.
_ECOSYSTEM_INDICATORS: dict[str, list[str]] = {
    "python": ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
    "node": ["package.json"],
    "rust": ["Cargo.toml"],
    "go": ["go.mod"],
}


def detect_ecosystems(target_dir: str) -> list[str]:
    """Scan *target_dir* for manifest files and return detected ecosystem names."""
    detected: list[str] = []
    base = Path(target_dir)
    for ecosystem, indicators in _ECOSYSTEM_INDICATORS.items():
        found = [f for f in indicators if (base / f).exists()]
        if found:
            detected.append(ecosystem)
            log.info("Detected %s ecosystem (found: %s)", ecosystem, ", ".join(found))
    if not detected:
        log.info("No package ecosystems detected in %s", target_dir)
    return detected


def _log_download_summary(ecosystem: str, output_dir: Path) -> None:
    """Log count and total size of downloaded artifacts."""
    if not output_dir.exists():
        return
    files = [f for f in output_dir.iterdir() if f.is_file() and not f.name.startswith("_")]
    total_size = sum(f.stat().st_size for f in files)
    if files:
        size_mb = total_size / (1024 * 1024)
        log.info("  %s: downloaded %d artifacts (%.1f MB)", ecosystem, len(files), size_mb)
        for f in sorted(files)[:5]:
            log.debug("    %s (%.1f KB)", f.name, f.stat().st_size / 1024)
        if len(files) > 5:
            log.debug("    ... and %d more", len(files) - 5)
    else:
        log.info("  %s: no artifacts downloaded", ecosystem)


# ── Download: Python ──────────────────────────────────────────────────────────


def _is_workspace_pyproject(pyproject: Path) -> bool:
    """True if the given pyproject.toml is a multi-package workspace
    (uv, poetry, hatch, rye, or PEP 621 with members)."""
    try:
        data = tomllib.loads(pyproject.read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return False
    tool = data.get("tool", {})
    if not isinstance(tool, dict):
        return False
    for key in ("uv", "poetry", "hatch", "rye"):
        section = tool.get(key, {})
        if isinstance(section, dict) and "workspace" in section:
            return True
    return False


def _glob_workspace_members(root: Path) -> list[Path]:
    """Return pyproject.toml paths for every workspace member.

    Reads ``[tool.uv.workspace] members`` (and falls back to common
    layouts) and resolves each glob relative to the root.
    """
    try:
        data = tomllib.loads((root / "pyproject.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return []

    members: list[str] = []
    tool = data.get("tool", {})
    if isinstance(tool, dict):
        uv = tool.get("uv", {})
        if isinstance(uv, dict):
            ws = uv.get("workspace", {})
            if isinstance(ws, dict):
                members = list(ws.get("members", []))
        # poetry uses [tool.poetry] packages — different shape, but for
        # workspace-style monorepos people commonly mirror the pattern
        # under [tool.poetry.workspace]
        poetry = tool.get("poetry", {})
        if isinstance(poetry, dict):
            ws = poetry.get("workspace", {})
            if isinstance(ws, dict):
                members.extend(ws.get("members", []))

    if not members:
        return []

    paths: list[Path] = []
    for pattern in members:
        for match in sorted(root.glob(pattern)):
            candidate = match / "pyproject.toml"
            if candidate.is_file():
                paths.append(candidate)
    return paths


def _extract_pep621_dependencies(pyproject: Path) -> list[str]:
    """Return ``[project] dependencies`` (and optional-dependencies) from
    a PEP 621 pyproject.toml. Returns an empty list on parse failure."""
    try:
        data = tomllib.loads(pyproject.read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return []
    project = data.get("project", {})
    if not isinstance(project, dict):
        return []
    deps: list[str] = list(project.get("dependencies", []) or [])
    optional = project.get("optional-dependencies", {}) or {}
    if isinstance(optional, dict):
        for group_deps in optional.values():
            if isinstance(group_deps, list):
                deps.extend(group_deps)
    return [d for d in deps if isinstance(d, str) and d.strip()]


def _build_workspace_requirements(root: Path, output_dir: Path) -> Path | None:
    """Synthesize a requirements file from a workspace pyproject + members.

    Walks the root pyproject and every member pyproject, collects all
    PEP 621 dependencies, dedupes them, and writes a single requirements
    file under ``output_dir``. Returns the path, or None when no
    dependencies could be extracted.
    """
    pyprojects = [root / "pyproject.toml"]
    pyprojects.extend(_glob_workspace_members(root))

    seen: set[str] = set()
    ordered: list[str] = []
    for pp in pyprojects:
        for dep in _extract_pep621_dependencies(pp):
            # Skip self-references like ``aegra-core`` between workspace
            # members — they would always fail on the index.
            if dep in seen:
                continue
            seen.add(dep)
            ordered.append(dep)

    if not ordered:
        return None

    req_path = output_dir / "_workspace_reqs.txt"
    req_path.write_text("\n".join(ordered) + "\n")
    log.info(
        "Workspace pyproject detected — synthesized %d unique deps from %d pyproject.toml files",
        len(ordered),
        len(pyprojects),
    )
    return req_path


def download_python(target_dir: str, deps_dir: str) -> None:
    """Download Python dependencies (source-only) using pip3 download.

    Workspace pyprojects (uv, poetry, hatch, rye, or any PEP 621 layout
    with workspace members) cannot be passed as a positional argument to
    pip download — setuptools tries to discover packages and explodes
    with "Multiple top-level packages discovered" on flat layouts.

    For workspace pyprojects we extract ``[project] dependencies`` from
    the root and every member, dedupe, and download by name.
    """
    output_dir = Path(deps_dir) / "python"
    output_dir.mkdir(parents=True, exist_ok=True)

    base = Path(target_dir)
    req_args: list[str] = []

    if (base / "requirements.txt").exists():
        req_args = ["-r", str(base / "requirements.txt")]
    elif (base / "pyproject.toml").exists():
        if _is_workspace_pyproject(base / "pyproject.toml"):
            ws_req = _build_workspace_requirements(base, output_dir)
            if ws_req is not None:
                req_args = ["-r", str(ws_req)]
            else:
                log.warning("Workspace pyproject has no extractable PEP 621 dependencies; skipping pip download")
                _record_status(
                    "python",
                    "skipped",
                    "workspace pyproject with no PEP 621 dependencies",
                )
                return
        else:
            req_args = [str(base)]
    elif (base / "setup.py").exists():
        req_args = [str(base)]
    elif (base / "Pipfile").exists():
        # Extract package names from [packages] section
        tmp_req = output_dir / "_pipfile_reqs.txt"
        _extract_pipfile_reqs(base / "Pipfile", tmp_req)
        if tmp_req.stat().st_size > 0:
            req_args = ["-r", str(tmp_req)]

    if not req_args:
        _record_status("python", "skipped", "no recognized manifest")
        return

    log.info("Downloading Python dependencies (source-only)...")
    cmd = ["pip3", "download", "--no-binary", ":all:", "-d", str(output_dir), *req_args]
    result = retry(cmd, label="pip3-download", attempts=3)
    if result.returncode != 0:
        log.warning("Some Python packages failed to download")
        _record_status(
            "python",
            "failed",
            f"pip3 download exited {result.returncode}",
        )
    else:
        _record_status("python", "ok")
    _log_download_summary("python", output_dir)


def _extract_pipfile_reqs(pipfile: Path, out: Path) -> None:
    """Write package names from Pipfile [packages] to *out*."""
    in_packages = False
    lines: list[str] = []
    for line in pipfile.read_text().splitlines():
        if line.strip() == "[packages]":
            in_packages = True
            continue
        if line.startswith("[") and in_packages:
            break
        if in_packages and "=" in line:
            name = line.split("=")[0].strip()
            if name:
                lines.append(name)
    out.write_text("\n".join(lines) + "\n" if lines else "")


# ── Download: Node ────────────────────────────────────────────────────────────


def download_node(target_dir: str, deps_dir: str) -> None:
    """Download Node.js dependencies using npm pack."""
    output_dir = Path(deps_dir) / "node"
    output_dir.mkdir(parents=True, exist_ok=True)

    pkg_json = Path(target_dir) / "package.json"
    if not pkg_json.exists():
        return

    try:
        pkg = json.loads(pkg_json.read_text())
    except json.JSONDecodeError:
        log.warning("Could not parse package.json")
        return

    deps: dict[str, str] = {}
    deps.update(pkg.get("dependencies") or {})
    deps.update(pkg.get("devDependencies") or {})

    if not deps:
        return

    log.info("Downloading %d Node.js dependencies...", len(deps))
    for name, version in deps.items():
        spec = f"{name}@{version}" if version and not version.startswith("file:") else name
        log.debug("  Packing %s", spec)
        result = retry(
            ["npm", "pack", spec],
            label=f"npm-pack-{name}",
            attempts=3,
            cwd=str(output_dir),
        )
        if result.returncode != 0:
            log.warning("Failed to pack %s", spec)
    _log_download_summary("node", output_dir)


# ── Download: Rust ────────────────────────────────────────────────────────────


def download_rust(target_dir: str, deps_dir: str) -> None:
    """Download Rust dependencies using cargo vendor."""
    output_dir = Path(deps_dir) / "rust"
    output_dir.mkdir(parents=True, exist_ok=True)

    if not (Path(target_dir) / "Cargo.toml").exists():
        return

    log.info("Downloading Rust dependencies...")

    with tempfile.TemporaryDirectory(prefix="thresher-rust-") as tmp:
        project_copy = Path(tmp) / "project"
        shutil.copytree(target_dir, str(project_copy))

        result = retry(
            ["cargo", "vendor", str(output_dir)],
            label="cargo-vendor",
            attempts=3,
            cwd=str(project_copy),
        )

        if result.returncode != 0:
            # Try nightly flag for lockfile v4
            lock = project_copy / "Cargo.lock"
            if lock.exists() and "version" in lock.read_text():
                log.info("Lockfile v4 detected, retrying with -Znext-lockfile-bump...")
                result2 = retry(
                    ["cargo", "-Znext-lockfile-bump", "vendor", str(output_dir)],
                    label="cargo-vendor-nightly",
                    attempts=3,
                    cwd=str(project_copy),
                )
                if result2.returncode != 0:
                    log.warning("cargo vendor failed (lockfile v4 incompatible)")
            else:
                log.warning("cargo vendor failed")
    _log_download_summary("rust", output_dir)


# ── Download: Go ──────────────────────────────────────────────────────────────


def download_go(target_dir: str, deps_dir: str) -> None:
    """Download Go dependencies using go mod vendor."""
    output_dir = Path(deps_dir) / "go"
    output_dir.mkdir(parents=True, exist_ok=True)

    if not (Path(target_dir) / "go.mod").exists():
        return

    log.info("Downloading Go dependencies...")

    with tempfile.TemporaryDirectory(prefix="thresher-go-") as tmp:
        project_copy = Path(tmp) / "project"
        shutil.copytree(target_dir, str(project_copy))
        gomodcache = Path(tmp) / "gomodcache"
        gomodcache.mkdir()

        env = {**os.environ, "GOMODCACHE": str(gomodcache)}
        result = retry(
            ["go", "mod", "vendor"],
            label="go-mod-vendor",
            attempts=3,
            cwd=str(project_copy),
            env=env,
        )

        if result.returncode != 0:
            log.warning("go mod vendor failed")
            return

        vendor_src = project_copy / "vendor"
        if vendor_src.exists():
            for item in vendor_src.iterdir():
                dest = output_dir / item.name
                if item.is_dir():
                    shutil.copytree(str(item), str(dest), dirs_exist_ok=True)
                else:
                    shutil.copy2(str(item), str(dest))
    _log_download_summary("go", output_dir)


# ── Download: Hidden deps ─────────────────────────────────────────────────────


def download_hidden(hidden_deps: dict, deps_dir: str, config) -> None:
    """Download hidden dependencies discovered by the pre-dep AI agent.

    Skips high-risk entries unless config.high_risk_dep is True.
    Writes skipped entries to hidden/skipped_high_risk.json.
    """
    output_dir = Path(deps_dir) / "hidden"
    output_dir.mkdir(parents=True, exist_ok=True)

    high_risk_dep: bool = bool(
        config.high_risk_dep if not isinstance(config, dict) else config.get("high_risk_dep", False)
    )
    deps_list: list[dict] = hidden_deps.get("hidden_dependencies", [])

    if not deps_list:
        log.info("No hidden dependencies to download.")
        return

    log.info("Downloading %d hidden dependencies...", len(deps_list))
    skipped_high_risk: list[dict] = []

    for i, dep in enumerate(deps_list):
        dep_type = dep.get("type", "unknown")
        source = dep.get("source", "")
        confidence = dep.get("confidence", "low")
        risk = dep.get("risk", "medium")
        found_in = dep.get("found_in", "unknown")

        tag = f"[{i + 1}/{len(deps_list)}]"

        if not source:
            log.info("%s SKIP: no source URL", tag)
            continue

        if confidence == "low":
            log.info("%s SKIP (low confidence): %s", tag, source)
            continue

        if risk == "high" and not high_risk_dep:
            log.warning("%s SKIP (high-risk, use --high-risk-dep to download): %s", tag, source)
            skipped_high_risk.append(dep)
            continue

        risk_label = f" [RISK:{risk}]" if risk == "high" else ""
        log.info("%s %s%s: %s (from %s)", tag, dep_type, risk_label, source, found_in)

        try:
            _fetch_hidden_dep(dep_type, source, i, output_dir)
        except Exception as exc:
            log.error("%s ERROR: %s", tag, exc)

    if skipped_high_risk:
        skipped_path = output_dir / "skipped_high_risk.json"
        skipped_path.write_text(json.dumps(skipped_high_risk, indent=2))
        log.warning(
            "%d high-risk dependencies were NOT downloaded. Use --high-risk-dep to include them.",
            len(skipped_high_risk),
        )


def _fetch_hidden_dep(dep_type: str, source: str, idx: int, output_dir: Path) -> None:
    """Fetch a single hidden dependency into *output_dir*."""
    if dep_type in ("git", "submodule"):
        dest = output_dir / f"{dep_type}-{idx}"
        clone_cmd = [
            "git",
            "clone",
            "--no-checkout",
            "--depth=1",
            "--single-branch",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.ext.allow=never",
            source,
            str(dest),
        ]
        if dep_type == "submodule":
            # Drop file/ext restrictions for local submodule paths
            clone_cmd = [
                "git",
                "clone",
                "--no-checkout",
                "--depth=1",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                source,
                str(dest),
            ]
        run_cmd(clone_cmd, label=f"git-clone-hidden-{idx}", timeout=120)
        env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0"}
        run_cmd(["git", "checkout"], label=f"git-checkout-hidden-{idx}", timeout=60, cwd=str(dest), env=env)
        log.info("    -> cloned to %s", dest)

    elif dep_type == "npm":
        pkg_dir = output_dir / f"npm-{idx}"
        pkg_dir.mkdir(parents=True, exist_ok=True)
        run_cmd(["npm", "pack", source], label=f"npm-pack-hidden-{idx}", timeout=120, cwd=str(pkg_dir))
        log.info("    -> downloaded to %s", pkg_dir)

    elif dep_type == "pypi":
        pkg_dir = output_dir / f"pypi-{idx}"
        pkg_dir.mkdir(parents=True, exist_ok=True)
        run_cmd(
            ["pip3", "download", "--no-binary", ":all:", "-d", str(pkg_dir), source],
            label=f"pip3-download-hidden-{idx}",
            timeout=120,
        )
        log.info("    -> downloaded to %s", pkg_dir)

    elif dep_type == "cargo":
        log.info("    -> cargo hidden deps not yet supported, flagged for scanning")

    elif dep_type == "go":
        log.info("    -> go hidden deps not yet supported, flagged for scanning")

    elif dep_type == "url":
        dest_dir = output_dir / f"url-{idx}"
        dest_dir.mkdir(parents=True, exist_ok=True)
        run_cmd(
            [
                "curl",
                "-fsSL",
                "--max-time",
                "60",
                "--max-filesize",
                str(50 * 1024 * 1024),
                "-o",
                str(dest_dir / "download"),
                "--proto",
                "=https,http",
                source,
            ],
            label=f"curl-hidden-{idx}",
            timeout=90,
        )
        log.info("    -> downloaded to %s", dest_dir)

    elif dep_type == "docker":
        log.info("    -> Docker image noted for analysis: %s", source)

    else:
        log.info("    -> unknown type, skipped")


# ── Build Manifest ────────────────────────────────────────────────────────────


def _parse_package_name(filename: str, ecosystem: str) -> tuple[str, str]:
    """Extract (name, version) from a downloaded artifact filename."""
    if ecosystem == "python":
        for suffix in (".tar.gz", ".zip"):
            if filename.endswith(suffix):
                base = filename[: -len(suffix)]
                parts = base.rsplit("-", 1)
                if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
                    return parts[0], parts[1]
                return base, "unknown"
        return filename, "unknown"

    elif ecosystem == "node":
        if filename.endswith(".tgz"):
            base = filename[: -len(".tgz")]
            parts = base.rsplit("-", 1)
            if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
                return parts[0], parts[1]
            return base, "unknown"
        return filename, "unknown"

    elif ecosystem in ("rust", "go"):
        parts = filename.rsplit("-", 1)
        if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
            return parts[0], parts[1]
        return filename, "unknown"

    return filename, "unknown"


_KNOWN_ECOSYSTEMS = {"python", "node", "rust", "go"}


def build_manifest(deps_dir: str) -> None:
    """Walk *deps_dir* and write dep_manifest.json."""
    manifest: dict[str, list[dict]] = {}
    base = Path(deps_dir)

    if not base.is_dir():
        result: dict = {"ecosystems": [], "dependencies": []}
        (base / "dep_manifest.json").parent.mkdir(parents=True, exist_ok=True)
        (Path(deps_dir) / "dep_manifest.json").write_text(json.dumps(result, indent=2) + "\n")
        return

    for ecosystem in sorted(os.listdir(deps_dir)):
        eco_path = base / ecosystem
        if not eco_path.is_dir():
            continue
        if ecosystem not in _KNOWN_ECOSYSTEMS:
            continue

        packages: list[dict] = []
        for entry in sorted(os.listdir(str(eco_path))):
            if entry.startswith("_"):
                continue  # skip temp files like _pipfile_reqs.txt
            name, version = _parse_package_name(entry, ecosystem)
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "path": str(eco_path / entry),
                }
            )
        manifest[ecosystem] = packages

    manifest_path = base / "dep_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    # Log summary
    total = sum(len(pkgs) for pkgs in manifest.values())
    ecosystems_found = list(manifest.keys())
    log.info("Dependency manifest: %d packages across %s", total, ecosystems_found)
    for eco, pkgs in manifest.items():
        log.info("  %s: %d packages", eco, len(pkgs))
        for pkg in pkgs[:10]:
            log.debug("    %s %s", pkg["name"], pkg["version"])
        if len(pkgs) > 10:
            log.debug("    ... and %d more", len(pkgs) - 10)


# ── Orchestrator ──────────────────────────────────────────────────────────────


def resolve_deps(
    target_dir: str,
    ecosystems: list[str],
    hidden_deps: dict,
    config: dict,
    deps_dir: str = "/opt/deps",
) -> str:
    """Download all dependencies and write dep_manifest.json + dep_resolution.json.

    Returns the path to the deps directory.
    """
    # Build the dispatch table inside the function so that monkeypatching
    # thresher.harness.deps.download_* in tests works correctly.
    import thresher.harness.deps as _self

    _downloaders = {
        "python": _self.download_python,
        "node": _self.download_node,
        "rust": _self.download_rust,
        "go": _self.download_go,
    }

    deps_path = Path(deps_dir)
    deps_path.mkdir(parents=True, exist_ok=True)

    # Activate the per-call status accumulator so download_* functions
    # can record their outcome via _record_status.
    global _current_status
    _current_status = DepResolutionStatus()
    try:
        for eco in ecosystems:
            downloader = _downloaders.get(eco)
            if downloader is None:
                log.warning("No downloader for ecosystem: %s", eco)
                _current_status.record(eco, "unknown", "no downloader")
                continue
            # Pre-record so the report still shows the ecosystem even if
            # the downloader is mocked or returns silently. The downloader
            # overrides this with a more specific status (ok / failed /
            # skipped).
            _current_status.record(eco, "ok", "")
            log.info("Resolving %s dependencies...", eco)
            try:
                downloader(target_dir, deps_dir)
            except Exception as exc:
                log.exception("Downloader for %s raised", eco)
                _current_status.record(eco, "failed", str(exc))

        if hidden_deps:
            _self.download_hidden(hidden_deps, deps_dir, config)

        _self.build_manifest(deps_dir)

        # Always persist a status file so the report can show ecosystem
        # coverage even when nothing failed.
        _current_status.write(deps_path)

        if _current_status.has_failures:
            log.warning(
                "One or more ecosystems failed to download — see %s",
                deps_path / "dep_resolution.json",
            )
    finally:
        _current_status = None

    log.info("Dependency resolution complete.")
    return deps_dir
