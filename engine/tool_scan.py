"""External tool scan connector for Garak, PyRIT, and DeepTeam."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from core.schemas import TargetConfig

ROOT_DIR = Path(__file__).resolve().parents[1]
TOOL_REPORT_DIR = ROOT_DIR / "reports" / "tool-scans"

GARAK_TARGET_TYPES = (
    "ollama",
    "openai",
    "azure",
    "groq",
    "huggingface",
    "bedrock",
    "litellm",
    "mistral",
    "rest",
    "websocket",
    "rasa",
    "cohere",
    "replicate",
    "watsonx",
    "nim",
    "nvcf",
    "ggml",
    "langchain",
    "langchain_serve",
)

GARAK_PROBE_PRESETS: dict[str, tuple[str, str]] = {
    "owasp": ("--probe_tags", "owasp"),
    "all": ("--probes", "all"),
    "prompt_injection": ("--probes", "promptinject.HijackHateHumans"),
    "dan": ("--probes", "dan.DanInTheWild"),
    "encoding": ("--probes", "encoding.InjectBase64"),
    "lmrc": ("--probes", "lmrc.Profanity"),
    "malwaregen": ("--probes", "malwaregen.TopLevel"),
    "sys_prompt": ("--probes", "sysprompt_extraction.SystemPromptExtraction"),
}

GARAK_COMMON_BUFFS = ("lowercase", "paraphrase.Fast", "paraphrase.PegasusT5")


@dataclass(frozen=True)
class ToolDefinition:
    id: str
    name: str
    executable: str
    purpose: str
    profiles: tuple[str, ...]
    install_hint: str


TOOL_DEFINITIONS: dict[str, ToolDefinition] = {
    "garak": ToolDefinition(
        id="garak",
        name="Garak",
        executable="garak",
        purpose="Probe LLM applications with model and plugin based vulnerability checks.",
        profiles=("quick", "standard", "deep"),
        install_hint="Install Garak in the backend environment, then restart the API process.",
    ),
    "pyrit": ToolDefinition(
        id="pyrit",
        name="PyRIT",
        executable="pyrit",
        purpose="Run prompt orchestration, scoring, and red-team attack workflows.",
        profiles=("quick", "standard", "deep"),
        install_hint="Install PyRIT in the backend environment, then restart the API process.",
    ),
    "deepteam": ToolDefinition(
        id="deepteam",
        name="DeepTeam",
        executable="deepteam",
        purpose="Evaluate adversarial prompts and model safety behavior across attack categories.",
        profiles=("quick", "standard", "deep"),
        install_hint="Install DeepTeam in the backend environment, then restart the API process.",
    ),
}


class ToolScanRequest(BaseModel):
    tool_id: str = Field(pattern="^(garak|pyrit|deepteam)$")
    target: TargetConfig | None = None
    profile: str = Field(default="standard", pattern="^(quick|standard|deep)$")
    options: str = ""
    timeout_seconds: int = Field(default=120, ge=5, le=1800)
    dry_run: bool = False
    garak_target_type: str = "ollama"
    garak_target_name: str = ""
    garak_probe_mode: Literal["owasp", "all", "prompt_injection", "dan", "encoding", "lmrc", "malwaregen", "sys_prompt", "custom_probe", "custom_tag"] = "owasp"
    garak_probe_value: str = ""
    garak_buffs: list[str] = Field(default_factory=list)

    @field_validator("garak_target_type")
    @classmethod
    def validate_garak_target_type(cls, value: str) -> str:
        if value not in GARAK_TARGET_TYPES:
            raise ValueError(f"Unsupported Garak target type: {value}")
        return value


class ToolScanResult(BaseModel):
    scan_id: str
    tool_id: str
    tool_name: str
    status: str
    started_at: datetime
    completed_at: datetime
    command: list[str]
    executable_path: str | None = None
    stdout: str = ""
    stderr: str = ""
    return_code: int | None = None
    error: str | None = None
    install_hint: str | None = None
    dry_run: bool = False
    report_paths: list[str] = Field(default_factory=list)


def list_tool_connectors() -> list[dict[str, Any]]:
    connectors: list[dict[str, Any]] = []
    for tool in TOOL_DEFINITIONS.values():
        executable_path = shutil.which(tool.executable)
        connectors.append(
            {
                "id": tool.id,
                "name": tool.name,
                "purpose": tool.purpose,
                "profiles": list(tool.profiles),
                "executable": tool.executable,
                "executable_path": executable_path,
                "available": executable_path is not None,
                "install_hint": tool.install_hint,
                "command_template": _command_template(tool.id),
                "target_types": list(GARAK_TARGET_TYPES) if tool.id == "garak" else [],
                "probe_modes": list(GARAK_PROBE_PRESETS.keys()) + ["custom_probe", "custom_tag"] if tool.id == "garak" else [],
                "buffs": list(GARAK_COMMON_BUFFS) if tool.id == "garak" else [],
            }
        )
    return connectors


def run_tool_scan(request: ToolScanRequest) -> ToolScanResult:
    tool = TOOL_DEFINITIONS[request.tool_id]
    started_at = datetime.now(UTC)
    executable_path = shutil.which(tool.executable)
    scan_id = str(uuid4())

    TOOL_REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="tool-scan-") as tmpdir:
        target_path: Path | None = None
        if request.target is not None:
            target_path = Path(tmpdir) / "target.json"
            target_path.write_text(json.dumps(request.target.model_dump(mode="json"), indent=2), encoding="utf-8")
        try:
            command, report_prefix = _build_command(tool, request, target_path, scan_id)
        except ValueError as exc:
            return ToolScanResult(
                scan_id=scan_id,
                tool_id=tool.id,
                tool_name=tool.name,
                status="FAILED",
                started_at=started_at,
                completed_at=datetime.now(UTC),
                command=[tool.executable],
                executable_path=executable_path,
                error=str(exc),
            )

        if request.dry_run:
            return ToolScanResult(
                scan_id=scan_id,
                tool_id=tool.id,
                tool_name=tool.name,
                status="VALIDATED",
                started_at=started_at,
                completed_at=datetime.now(UTC),
                command=command,
                executable_path=executable_path,
                dry_run=True,
                install_hint=None if executable_path else tool.install_hint,
                report_paths=_matching_reports(report_prefix),
            )

        if executable_path is None:
            return ToolScanResult(
                scan_id=scan_id,
                tool_id=tool.id,
                tool_name=tool.name,
                status="FAILED",
                started_at=started_at,
                completed_at=datetime.now(UTC),
                command=command,
                error=f"{tool.name} executable '{tool.executable}' was not found on PATH.",
                install_hint=tool.install_hint,
                report_paths=_matching_reports(report_prefix),
            )

        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=request.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolScanResult(
                scan_id=scan_id,
                tool_id=tool.id,
                tool_name=tool.name,
                status="FAILED",
                started_at=started_at,
                completed_at=datetime.now(UTC),
                command=command,
                executable_path=executable_path,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                error=f"{tool.name} scan timed out after {request.timeout_seconds} seconds.",
                report_paths=_matching_reports(report_prefix),
            )
        except OSError as exc:
            return ToolScanResult(
                scan_id=scan_id,
                tool_id=tool.id,
                tool_name=tool.name,
                status="FAILED",
                started_at=started_at,
                completed_at=datetime.now(UTC),
                command=command,
                executable_path=executable_path,
                error=str(exc),
                report_paths=_matching_reports(report_prefix),
            )

    return ToolScanResult(
        scan_id=scan_id,
        tool_id=tool.id,
        tool_name=tool.name,
        status="COMPLETED" if completed.returncode == 0 else "FAILED",
        started_at=started_at,
        completed_at=datetime.now(UTC),
        command=command,
        executable_path=executable_path,
        stdout=completed.stdout,
        stderr=completed.stderr,
        return_code=completed.returncode,
        report_paths=_matching_reports(report_prefix),
    )


def _build_command(tool: ToolDefinition, request: ToolScanRequest, target_path: Path | None, scan_id: str) -> tuple[list[str], Path | None]:
    if tool.id == "garak":
        command, report_prefix = _build_garak_command(tool, request, scan_id)
    elif tool.id == "pyrit":
        if target_path is None:
            raise ValueError("PyRIT scans require a saved target configuration.")
        report_prefix = None
        command = [tool.executable, "scan", "--target", str(target_path), "--profile", request.profile]
    else:
        if target_path is None:
            raise ValueError("DeepTeam scans require a saved target configuration.")
        report_prefix = None
        command = [tool.executable, "run", "--target", str(target_path), "--profile", request.profile]

    if request.options.strip():
        command.extend(shlex.split(request.options))
    return command, report_prefix


def _build_garak_command(tool: ToolDefinition, request: ToolScanRequest, scan_id: str) -> tuple[list[str], Path]:
    target_name = request.garak_target_name.strip()
    if not target_name:
        raise ValueError("Garak model name is required.")

    report_prefix = TOOL_REPORT_DIR / f"garak-{scan_id}"
    command = [
        tool.executable,
        "--target_type",
        request.garak_target_type,
        "--target_name",
        target_name,
    ]

    if request.garak_probe_mode in GARAK_PROBE_PRESETS:
        flag, value = GARAK_PROBE_PRESETS[request.garak_probe_mode]
    else:
        value = request.garak_probe_value.strip()
        if not value:
            raise ValueError("Select or enter a Garak probe value.")
        flag = "--probes" if request.garak_probe_mode == "custom_probe" else "--probe_tags"

    command.extend([flag, value, "--report_prefix", str(report_prefix)])
    buffs = [buff.strip() for buff in request.garak_buffs if buff.strip()]
    if buffs:
        command.extend(["--buffs", ",".join(buffs)])
    return command, report_prefix


def _matching_reports(report_prefix: Path | None) -> list[str]:
    if report_prefix is None:
        return []
    return sorted(str(path) for path in report_prefix.parent.glob(f"{report_prefix.name}*") if path.is_file())


def _command_template(tool_id: str) -> str:
    if tool_id == "garak":
        return "garak --target_type ollama --target_name llama3.2 --probe_tags owasp --buffs lowercase,paraphrase.Fast --report_prefix reports/tool-scans/garak-<scan_id>"
    if tool_id == "pyrit":
        return "pyrit scan --target target.json --profile standard"
    return "deepteam run --target target.json --profile standard"
