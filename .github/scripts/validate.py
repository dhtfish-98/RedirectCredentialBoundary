"""Build, install, and exercise the isolated RedirectCredentialBoundary project."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "Build"
SOURCE = ROOT
DOC_DIR = ROOT / "项目文档"
DOC = DOC_DIR / "README.md"
DOC_LICENSE = DOC_DIR / "LICENSE"
STAGE = BUILD / "stage"
DIST = BUILD / "dist"
VENV = BUILD / "venv"
CONSUMER = BUILD / "consumer"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(label: str, argv: list[str], cwd: Path, env: dict[str, str]) -> dict[str, object]:
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, check=False)
    log_path = BUILD / f"{label}.log"
    log_path.write_text(result.stdout + result.stderr)
    return {
        "label": label,
        "argv": argv,
        "cwd": str(cwd),
        "exit_code": result.returncode,
        "log_path": str(log_path),
        "log_sha256": sha256(log_path),
    }


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    DIST.mkdir(exist_ok=True)
    CONSUMER.mkdir(exist_ok=True)
    source_files = sorted(
        [SOURCE / "pyproject.toml", SOURCE / ".github/scripts/validate.py"]
        + [file for base in (SOURCE / "src", SOURCE / "tests") for file in base.rglob("*") if file.is_file()]
    )
    files = [{"path": str(file.relative_to(SOURCE)), "sha256": sha256(file)} for file in source_files]
    config = tomllib.loads((SOURCE / "pyproject.toml").read_text())
    expected_version = config["project"]["version"]
    receipt: dict[str, object] = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "project": "RedirectCredentialBoundary",
        "version": expected_version,
        "author": config["project"]["authors"][0]["name"],
        "source_root": str(SOURCE),
        "documentation": str(DOC),
        "license_document": str(DOC_LICENSE),
        "source_files": files,
        "source_manifest_sha256": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
        "documentation_sha256": sha256(DOC),
        "license_document_sha256": sha256(DOC_LICENSE),
        "commands": [],
        "checks": {},
        "status": "OPEN",
    }
    commands = receipt["commands"]
    checks = receipt["checks"]
    assert isinstance(commands, list) and isinstance(checks, dict)
    env = os.environ.copy()
    env["UV_CACHE_DIR"] = str(BUILD / "uv-cache")
    env["PYTHONPYCACHEPREFIX"] = str(BUILD / "pycache")
    source_env = env.copy()
    source_env["PYTHONPATH"] = str(SOURCE / "src")

    def step(label: str, argv: list[str], cwd: Path, step_env: dict[str, str]) -> bool:
        outcome = command(label, argv, cwd, step_env)
        commands.append(outcome)
        checks[label] = outcome["exit_code"] == 0
        return bool(checks[label])

    try:
        if not step("source-tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], SOURCE, source_env):
            return 1
        if not step("source-lab", [sys.executable, str(SOURCE / "tests/run_local_experiment.py"), str(BUILD / "lab-source.json")], SOURCE, source_env):
            return 1
        if STAGE.exists():
            shutil.rmtree(STAGE)
        STAGE.mkdir(parents=True)
        shutil.copy2(SOURCE / "pyproject.toml", STAGE / "pyproject.toml")
        for directory in ("src", "tests"):
            shutil.copytree(
                SOURCE / directory, STAGE / directory,
                ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"),
            )
        shutil.copy2(DOC_LICENSE, STAGE / "LICENSE")
        checks["staged_license_equals_document"] = sha256(STAGE / "LICENSE") == sha256(DOC_LICENSE)
        for pattern in ("*.whl", "*.tar.gz"):
            for artifact in DIST.glob(pattern):
                artifact.unlink()
        if not step("build", ["uv", "build", "--out-dir", str(DIST)], STAGE, env):
            return 1
        wheels = sorted(DIST.glob("*.whl"))
        sdists = sorted(DIST.glob("*.tar.gz"))
        checks["one_wheel_one_sdist"] = len(wheels) == 1 and len(sdists) == 1
        if not checks["one_wheel_one_sdist"]:
            return 1
        wheel, sdist = wheels[0], sdists[0]
        with zipfile.ZipFile(wheel) as archive:
            wheel_entries = sorted(archive.namelist())
            metadata_name = next(name for name in wheel_entries if name.endswith(".dist-info/METADATA"))
            wheel_metadata = archive.read(metadata_name).decode("utf-8")
        with tarfile.open(sdist, "r:gz") as archive:
            sdist_entries = sorted(archive.getnames())
        checks["wheel_contains_runtime_and_own_license"] = (
            "redirect_credential_boundary/client.py" in wheel_entries
            and "redirect_credential_boundary/__init__.py" in wheel_entries
            and any(name.endswith(".dist-info/licenses/LICENSE") for name in wheel_entries)
            and not any("/tests/" in name for name in wheel_entries)
        )
        checks["sdist_contains_sources_tests_license"] = all(
            any(name.endswith(suffix) for name in sdist_entries)
            for suffix in ("/src/redirect_credential_boundary/client.py", "/tests/test_redirect_policy.py", "/LICENSE", "/pyproject.toml")
        )
        checks["wheel_metadata_author_version_license"] = all(
            line in wheel_metadata.splitlines()
            for line in (
                "Name: redirect-credential-boundary",
                f"Version: {expected_version}",
                "Author: dhtfish98",
                "License-Expression: MIT",
            )
        )
        receipt["artifacts"] = {
            "wheel": {"path": str(wheel), "sha256": sha256(wheel), "entries": wheel_entries},
            "sdist": {"path": str(sdist), "sha256": sha256(sdist), "entries": sdist_entries},
        }
        if not all((checks["wheel_contains_runtime_and_own_license"], checks["sdist_contains_sources_tests_license"], checks["wheel_metadata_author_version_license"])):
            return 1
        if not step("venv", ["uv", "venv", "--clear", "--python", sys.executable, str(VENV)], CONSUMER, env):
            return 1
        installed_python = str(VENV / "bin/python")
        if not step("install-wheel", ["uv", "pip", "install", "--python", installed_python, "--no-deps", str(wheel)], CONSUMER, env):
            return 1
        installed_env = env.copy()
        installed_env.pop("PYTHONPATH", None)
        version_check = (
            "import redirect_credential_boundary as r; "
            "from pathlib import Path; "
            f"assert r.__version__ == {expected_version!r}; "
            f"assert str(Path(r.__file__).resolve()).startswith({str(VENV.resolve())!r}); "
            "print(r.__version__, r.__file__)"
        )
        if not step("installed-import", [installed_python, "-c", version_check], CONSUMER, installed_env):
            return 1
        if not step("installed-tests", [installed_python, "-m", "unittest", "discover", "-s", str(SOURCE / "tests"), "-v"], CONSUMER, installed_env):
            return 1
        if not step("installed-lab", [installed_python, str(SOURCE / "tests/run_local_experiment.py"), str(BUILD / "lab-installed.json")], CONSUMER, installed_env):
            return 1
        source_lab = json.loads((BUILD / "lab-source.json").read_text())
        installed_lab = json.loads((BUILD / "lab-installed.json").read_text())
        checks["both_lab_receipts_pass"] = source_lab["result"] == installed_lab["result"] == "PASS"
        checks["author_and_version"] = receipt["author"] == "dhtfish98" and expected_version == "0.1.0"
        checks["source_tree_has_no_build_products"] = not any(
            part in {"__pycache__", "dist", "build", ".venv"}
            for base in (SOURCE / "src", SOURCE / "tests") for file in base.rglob("*") for part in file.parts
        )
        checks["source_tree_has_no_documents"] = not any(
            file.is_file() and (file.name == "LICENSE" or file.suffix.lower() in {".md", ".rst", ".txt"})
            for base in (SOURCE / "src", SOURCE / "tests") for file in base.rglob("*")
        )
        return 0 if all(checks.values()) else 1
    finally:
        receipt["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        receipt["status"] = "PASS" if checks and all(checks.values()) else "FAIL"
        (BUILD / "validation.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
        print(receipt["status"], BUILD / "validation.json")


if __name__ == "__main__":
    raise SystemExit(main())
