from __future__ import annotations

import asyncio
import csv
import importlib.util
import json
import os
import platform
import socket
import sys
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from nicegui import html, ui

from src.llm_profiles import LlmProfile, delete_llm_profile, list_llm_profiles, load_llm_profile, save_llm_profile, validate_llm_profile
from src.module_config import load_module_runtime_config, write_module_runtime_config
from src.prompt_profiles import (
    PromptProfile,
    list_prompt_profiles,
    load_prompt_profile,
    save_prompt_profile,
    validate_prompt_profile,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUTS_ROOT = PROJECT_ROOT / "outputs"
REPORTS_ROOT = PROJECT_ROOT / "reports"
MODULES_ROOT = PROJECT_ROOT / "modules"
TEST_SUITES_ROOT = PROJECT_ROOT / "config" / "test_suites"
LOCAL_TZ = ZoneInfo("Europe/Luxembourg")
LOCKED_PROMPT_PROFILES = {"default"}
SUSPICIOUS_DNS_TOKENS = {
    "login",
    "password",
    "verify",
    "invoice",
    "paypal",
    "micros0ft",
    "microsoft",
    "sharepoint",
    "secure",
    "portal",
}


def _module_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if not MODULES_ROOT.exists():
        return rows
    for module_dir in sorted(path for path in MODULES_ROOT.iterdir() if path.is_dir()):
        runner = module_dir / "runner.py"
        rows.append(
            {
                "module": module_dir.name,
                "status": "detected" if runner.exists() else "source only",
                "runner": str(runner.relative_to(PROJECT_ROOT)) if runner.exists() else "",
            }
        )
    return rows


def _module_runner_instance(module_name: str) -> Any | None:
    runner_path = MODULES_ROOT / module_name / "runner.py"
    if not runner_path.exists():
        return None
    spec = importlib.util.spec_from_file_location(f"gui_runner_{module_name}", runner_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    runner_class = getattr(module, "Runner", None)
    if runner_class is None:
        return None
    return runner_class()


def _module_validation_manifest_path(module_name: str) -> Path | None:
    module_dir = MODULES_ROOT / module_name
    for path in [
        module_dir / "telemetry_manifest.json",
        module_dir / "validation_manifest.json",
        module_dir / "validation" / "manifest.json",
        module_dir / "telemetry_options.json",
        module_dir / "evidence_options.json",
    ]:
        if path.exists():
            return path
    return None


def _module_validation_manifest(module_name: str) -> dict[str, Any]:
    path = _module_validation_manifest_path(module_name)
    if path is None:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "warning": f"Validation manifest could not be read: {exc}",
            "manifest_path": str(path.relative_to(PROJECT_ROOT)),
        }
    if not isinstance(data, dict):
        return {
            "warning": "Validation manifest must be a JSON object.",
            "manifest_path": str(path.relative_to(PROJECT_ROOT)),
        }
    data["manifest_path"] = str(path.relative_to(PROJECT_ROOT))
    return data


def _module_validation_capability(module_name: str) -> dict[str, Any]:
    manifest = _module_validation_manifest(module_name)
    options = manifest.get("validation") if isinstance(manifest.get("validation"), dict) else manifest
    if options:
        conditions = options.get("conditions") if isinstance(options.get("conditions"), dict) else {}
        scopes = options.get("scopes") if isinstance(options.get("scopes"), dict) else {}
        return {
            "conditions": conditions or {"off": "Off", "nominal": "Nominal telemetry"},
            "scopes": scopes or {"module_default": "Module default"},
            "default_condition": str(options.get("default_condition") or "nominal"),
            "default_scope": str(options.get("default_scope") or "module_default"),
            "supports_true_positive": bool(options.get("supports_true_positive", "actionable_issue" in conditions)),
            "warning": str(options.get("warning") or manifest.get("warning") or ""),
            "manifest_path": str(manifest.get("manifest_path") or ""),
            "manifest": manifest,
        }

    runner = _module_runner_instance(module_name)
    if runner is None or not hasattr(runner, "validation_options"):
        return {
            "conditions": {
                "off": "Off",
                "nominal": "Nominal telemetry",
            },
            "scopes": {"module_default": "Module default"},
            "default_condition": "nominal",
            "default_scope": "module_default",
            "supports_true_positive": False,
            "warning": "This module has not exposed validation telemetry options yet.",
            "manifest_path": "",
            "manifest": {},
        }
    options = runner.validation_options()
    if not isinstance(options, dict):
        options = {}
    conditions = options.get("conditions") if isinstance(options.get("conditions"), dict) else {}
    scopes = options.get("scopes") if isinstance(options.get("scopes"), dict) else {}
    return {
        "conditions": conditions or {"off": "Off", "nominal": "Nominal telemetry"},
        "scopes": scopes or {"module_default": "Module default"},
        "default_condition": str(options.get("default_condition") or "nominal"),
        "default_scope": str(options.get("default_scope") or "module_default"),
        "supports_true_positive": bool(options.get("supports_true_positive", "actionable_issue" in conditions)),
        "warning": str(options.get("warning") or ""),
        "manifest_path": "",
        "manifest": {},
    }


def _module_settings_surfaces(module_name: str) -> list[dict[str, str]]:
    module_dir = MODULES_ROOT / module_name
    source_dir = module_dir / "source"
    surfaces: list[dict[str, str]] = []

    for manifest_path in [
        module_dir / "module_controls.json",
        module_dir / "settings_surfaces.json",
        source_dir / "module_controls.json",
        source_dir / "settings_surfaces.json",
    ]:
        if not manifest_path.exists():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        raw_surfaces = manifest.get("settings_surfaces", manifest) if isinstance(manifest, dict) else manifest
        if not isinstance(raw_surfaces, list):
            continue
        for raw_surface in raw_surfaces:
            if not isinstance(raw_surface, dict):
                continue
            surface = {str(key): str(value) for key, value in raw_surface.items() if value is not None}
            surface.setdefault("kind", "web")
            surface.setdefault("label", f"{module_name} controls")
            surface.setdefault("detail", f"Control surface declared by `{manifest_path.relative_to(PROJECT_ROOT)}`.")
            surface.setdefault("command", "")
            surface.setdefault("url", "")
            surfaces.append(surface)

    web_doc = source_dir / "docs" / "WEB_UI.md"
    web_py_candidates = [source_dir / "web.py", source_dir / "src" / "ngo_intel" / "web.py"]
    has_web_py = any(path.exists() for path in web_py_candidates)
    has_web_doc = web_doc.exists()

    if has_web_py or has_web_doc:
        if module_name == "threatsucker":
            surfaces.append(
                {
                    "kind": "web",
                    "label": "ThreatSucker controls page",
                    "detail": "Local Flask control surface for source feeds, config sets, YAML validation, and allowlists.",
                    "command": "cd modules/threatsucker/source && uv run threatsucker web --host 127.0.0.1 --port 8765",
                    "cwd": "modules/threatsucker/source",
                    "argv": "uv run threatsucker web --host 127.0.0.1 --port 8765",
                    "host": "127.0.0.1",
                    "port": "8765",
                    "url": "http://127.0.0.1:8765",
                }
            )
        elif module_name == "sitechecker":
            surfaces.append(
                {
                    "kind": "web",
                    "label": "SiteChecker controls page",
                    "detail": "Local controls for owner-authorized single-website checks, target URL, enabled checks, and validation.",
                    "command": "uv run python modules/sitechecker/source/web.py --host 127.0.0.1 --port 8775",
                    "cwd": ".",
                    "argv": "uv run python modules/sitechecker/source/web.py --host 127.0.0.1 --port 8775",
                    "host": "127.0.0.1",
                    "port": "8775",
                    "url": "http://127.0.0.1:8775",
                }
            )
        else:
            surfaces.append(
                {
                    "kind": "web",
                    "label": "Web controls detected",
                    "detail": "A web.py or WEB_UI.md file was found. Startup command is not declared by the module.",
                    "command": "",
                    "url": "",
                }
            )

    config_paths = [
        path
        for path in [
            source_dir / "config",
            source_dir / "config_sets",
            module_dir / "config",
            module_dir / "config_sets",
        ]
        if path.exists()
    ]
    config_files = sorted(source_dir.glob("config*.toml")) + sorted(source_dir.glob("config*.yaml")) + sorted(source_dir.glob("config*.yml"))
    if config_paths or config_files:
        details = [str(path.relative_to(PROJECT_ROOT)) for path in [*config_paths, *config_files]]
        surfaces.append(
            {
                "kind": "config",
                "label": "Config files detected",
                "detail": ", ".join(details[:4]) + (" ..." if len(details) > 4 else ""),
                "command": "",
                "url": "",
            }
        )

    return surfaces


def _module_config_surface(module_name: str) -> dict[str, str] | None:
    for surface in _module_settings_surfaces(module_name):
        if surface.get("kind") == "config":
            return surface
    return None


def _local_tcp_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.25):
            return True
    except OSError:
        return False


def _run_dirs() -> list[Path]:
    if not OUTPUTS_ROOT.exists():
        return []
    return sorted((path for path in OUTPUTS_ROOT.iterdir() if path.is_dir()), reverse=True)


def _run_options() -> dict[str, str]:
    return {path.name: _run_display_label(path.name) for path in _run_dirs()}


def _json_files(run_name: str) -> dict[str, str]:
    run_dir = OUTPUTS_ROOT / run_name
    if not run_dir.exists():
        return {}
    return {
        str(path.relative_to(run_dir)): str(path.relative_to(run_dir))
        for path in sorted(run_dir.rglob("*.json"))
    }


def _evidence_files(run_name: str) -> dict[str, str]:
    run_dir = OUTPUTS_ROOT / run_name
    if not run_dir.exists():
        return {}
    supported = {".json", ".jsonl", ".csv", ".txt", ".md", ".log"}
    return {
        str(path.relative_to(run_dir)): str(path.relative_to(run_dir))
        for path in sorted(run_dir.rglob("*"))
        if path.is_file() and path.suffix.lower() in supported
    }


def _module_names_for_run(run_name: str) -> list[str]:
    run_dir = OUTPUTS_ROOT / run_name
    if not run_dir.exists():
        return []
    return sorted(path.name for path in run_dir.iterdir() if path.is_dir())


def _report_files() -> list[Path]:
    if not REPORTS_ROOT.exists():
        return []
    return sorted(REPORTS_ROOT.glob("*.md"), reverse=True)


def _is_validation_report(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "prompt developer telemetry payload:" in text or "prompt developer evidence payload:" in text or "background_noise/" in text


def _report_options(include_validation: bool = False) -> dict[str, str]:
    options: dict[str, str] = {}
    for path in _report_files():
        is_validation = _is_validation_report(path)
        if is_validation and not include_validation:
            continue
        label = _report_display_label(path.name)
        options[path.name] = f"VALIDATION - {label}" if is_validation else label
    return options


def _latest_report_text(validation_only: bool = False) -> str:
    reports = [path for path in _report_files() if not validation_only or _is_validation_report(path)]
    if not reports:
        return "Run a prompt check to see the LLM output here."
    return reports[0].read_text(encoding="utf-8")


def _manifest_runtime_config_markdown(manifest: dict[str, Any]) -> str:
    runtime_config = manifest.get("module_runtime_config")
    if not isinstance(runtime_config, dict):
        legacy_config: dict[str, Any] = {}
        if isinstance(manifest.get("dnscap_import"), dict):
            legacy_config["dnscap"] = manifest["dnscap_import"]
        if isinstance(manifest.get("threatsucker_config"), dict):
            legacy_config["threatsucker"] = manifest["threatsucker_config"]
        runtime_config = legacy_config
    if not runtime_config:
        return "**Runtime configs:** `not recorded`"

    lines = ["**Runtime configs:**"]
    for module_name, config in sorted(runtime_config.items()):
        if not isinstance(config, dict):
            continue
        compact = json.dumps(config, sort_keys=True)
        if len(compact) > 220:
            compact = compact[:217] + "..."
        lines.append(f"- `{module_name}`: `{compact}`")
    return "\n".join(lines) if len(lines) > 1 else "**Runtime configs:** `not recorded`"


def _parse_run_datetime(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H-%M-%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _european_datetime_label(value: str) -> str:
    parsed = _parse_run_datetime(value)
    if parsed is None:
        return value
    local = parsed.astimezone(LOCAL_TZ)
    return local.strftime("%d/%m/%Y %H:%M %Z")


def _run_display_label(run_name: str) -> str:
    return f"{_european_datetime_label(run_name)} ({run_name})"


def _report_display_label(report_name: str) -> str:
    run_name = _run_name_from_report(report_name)
    if not run_name:
        return report_name
    return f"{_european_datetime_label(run_name)} - {report_name}"


def _current_machine_label() -> str:
    return f"{socket.gethostname()} / {platform.platform()}"


def _rough_token_estimate(*parts: str) -> int:
    text = "\n".join(part or "" for part in parts)
    return max(1, int(len(text) / 3.7))


def _llm_capacity_markdown(profile: LlmProfile, evidence_text: str, prompt: PromptProfile) -> str:
    estimated = _rough_token_estimate(prompt.system_prompt, prompt.user_prompt, evidence_text)
    reserve = max(1024, int(profile.context_size * 0.15))
    usable = max(0, profile.context_size - reserve)
    status = "OK" if estimated <= usable else "Too large"
    return (
        f"**Context estimate:** `{estimated:,}` tokens / usable `{usable:,}` "
        f"of `{profile.context_size:,}` configured.\n\n"
        f"**Status:** `{status}`"
    )


def _parse_config_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if len(text) == 10:
        text = f"{text}T00:00:00+00:00"
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _dnscap_window_from_config(config: dict[str, Any]) -> tuple[str, datetime | None, datetime | None]:
    aliases = {
        "": "all",
        "all": "all",
        "forever": "all",
        "day": "last_day",
        "last_day": "last_day",
        "week": "last_week",
        "last_week": "last_week",
        "month": "last_month",
        "last_month": "last_month",
        "year": "last_year",
        "last_year": "last_year",
        "since_last_run": "since_last_scan",
        "since_last_scan": "since_last_scan",
        "custom": "custom",
        "range": "custom",
        "time_period": "custom",
    }
    period = aliases.get(str(config.get("period") or "all").strip().lower(), "all")
    end = _parse_config_datetime(config.get("end")) or datetime.now(UTC)
    start = _parse_config_datetime(config.get("start"))
    if period == "since_last_scan":
        start = _parse_config_datetime(config.get("last_run_utc"))
        if start is None:
            period = "all"
            end = None
    elif period == "last_day":
        start = start or end - timedelta(days=1)
    elif period == "last_week":
        start = start or end - timedelta(weeks=1)
    elif period == "last_month":
        start = start or end - timedelta(days=31)
    elif period == "last_year":
        start = start or end - timedelta(days=366)
    elif period == "custom":
        period = "custom"
    else:
        period = "all"
        start = None
        end = None
    return period, start, end


def _dnscap_estimated_payload_text(config: dict[str, Any]) -> str:
    root_value = str(config.get("log_root") or "sample_logs")
    root = Path(root_value)
    if not root.is_absolute():
        root = MODULES_ROOT / "dnscap" / root
    if not root.exists():
        return f"DNScap configured source not found: {root}"
    files: list[Path] = []
    if root.is_file():
        files = [root]
    else:
        for pattern in ["dns.jsonl", "dns.csv", "*.dns.jsonl", "*.dns.csv"]:
            files.extend(root.rglob(pattern))
        files = sorted(set(files))
    period, start, end = _dnscap_window_from_config(config)
    kept = 0
    total = 0
    sample_lines: list[str] = []
    for path in files[:200]:
        try:
            if path.suffix == ".jsonl":
                rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            elif path.suffix == ".csv":
                with path.open(newline="", encoding="utf-8") as handle:
                    rows = list(csv.DictReader(handle))
            else:
                continue
        except Exception:
            continue
        total += len(rows)
        for row in rows:
            ts = _parse_config_datetime(row.get("ts"))
            if start is not None and (ts is None or ts < start):
                continue
            if end is not None and (ts is None or ts > end):
                continue
            kept += 1
            if len(sample_lines) < 50:
                sample_lines.append(json.dumps({"host": row.get("host"), "qname": row.get("qname"), "ts": row.get("ts")}, sort_keys=True))
    return "\n".join(
        [
            f"dnscap period={period} files={len(files)} events_after_window={kept} events_total={total}",
            *sample_lines,
        ]
    )


def _latest_module_payload_text(module_name: str, max_chars: int = 40000) -> str:
    runs = sorted([path for path in OUTPUTS_ROOT.iterdir() if path.is_dir()], reverse=True) if OUTPUTS_ROOT.exists() else []
    for run_dir in runs:
        module_dir = run_dir / module_name
        if not module_dir.exists():
            continue
        chunks: list[str] = []
        for path in sorted(module_dir.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".json", ".jsonl", ".txt", ".md", ".csv"}:
                continue
            try:
                chunks.append(path.read_text(encoding="utf-8", errors="replace")[:max_chars])
            except Exception:
                continue
            if sum(len(chunk) for chunk in chunks) >= max_chars:
                break
        if chunks:
            return "\n".join(chunks)[:max_chars]
    fallback_sizes = {
        "enumeros": 8000,
        "safesniff": 8000,
        "threatsucker": 14000,
        "sitechecker": 10000,
        "example_module": 1500,
    }
    return f"{module_name} estimated module payload\n" + ("x" * fallback_sizes.get(module_name, 5000))


def _assessment_context_capacity_markdown(prompt_name: str, llm_profile_name: str | None, enabled_modules: dict[str, bool]) -> str:
    prompt = load_prompt_profile(prompt_name or "default")
    profile = load_llm_profile(llm_profile_name or None)
    module_chunks: list[str] = []
    module_notes: list[str] = []
    for module_name, enabled in sorted(enabled_modules.items()):
        if not enabled:
            continue
        if module_name == "dnscap":
            text = _dnscap_estimated_payload_text(load_module_runtime_config(MODULES_ROOT / "dnscap"))
        else:
            text = _latest_module_payload_text(module_name)
        module_chunks.append(text)
        module_notes.append(f"`{module_name}` ~ `{_rough_token_estimate(text):,}`")
    evidence_text = "\n\n".join(module_chunks)
    estimated = _rough_token_estimate(prompt.system_prompt, prompt.user_prompt, evidence_text)
    reserve = max(1024, int(profile.context_size * 0.15))
    usable = max(0, profile.context_size - reserve)
    status = "OK" if estimated <= usable else "Too large"
    notes = ", ".join(module_notes) if module_notes else "No enabled modules"
    return (
        f"**Context estimate:** `{estimated:,}` / usable `{usable:,}` of `{profile.context_size:,}` tokens\n\n"
        f"**Status:** `{status}`\n\n"
        f"**Module estimate:** {notes}"
    )


def _local_llm_health(profile: LlmProfile) -> str:
    if not profile.base_url.startswith("http"):
        return "Not an HTTP endpoint."
    health_url = profile.base_url.rstrip("/").removesuffix("/v1") + "/health"
    try:
        with urllib.request.urlopen(health_url, timeout=1.5) as response:
            return f"Running ({response.status}) at `{profile.base_url}`."
    except Exception:
        return f"Not reachable at `{profile.base_url}`."


def _default_dnscap_log_root() -> str:
    config_root = load_module_runtime_config(MODULES_ROOT / "dnscap").get("log_root")
    if config_root:
        return str(config_root)
    imported = MODULES_ROOT / "dnscap" / "imported_logs"
    sample = MODULES_ROOT / "dnscap" / "sample_logs"
    if imported.exists():
        return str(imported)
    return str(sample)


def _default_dnscap_period() -> str:
    aliases = {
        "forever": "all",
        "day": "last_day",
        "week": "last_week",
        "month": "last_month",
        "year": "last_year",
        "since_last_run": "since_last_scan",
    }
    period = str(load_module_runtime_config(MODULES_ROOT / "dnscap").get("period") or "all")
    period = aliases.get(period, period)
    return period if period in {"all", "last_day", "last_week", "last_month", "last_year", "custom", "since_last_scan"} else "all"


def _run_name_from_report(report_name: str) -> str | None:
    prefix = "security_report_"
    suffix = ".md"
    if not report_name.startswith(prefix) or not report_name.endswith(suffix):
        return None
    return report_name[len(prefix):-len(suffix)]


def _latest_report_for_run(run_name: str) -> Path | None:
    manifest_path = OUTPUTS_ROOT / run_name / "run_manifest.json"
    if manifest_path.exists():
        try:
            report_path = Path(json.loads(manifest_path.read_text(encoding="utf-8")).get("report_path", ""))
            if report_path.exists():
                return report_path
        except json.JSONDecodeError:
            pass

    suffix = run_name.replace(":", "-")
    candidate = REPORTS_ROOT / f"security_report_{suffix}.md"
    return candidate if candidate.exists() else None


def _pretty_json(path: Path) -> str:
    try:
        return json.dumps(json.loads(path.read_text(encoding="utf-8")), indent=2, sort_keys=True)
    except json.JSONDecodeError:
        return path.read_text(encoding="utf-8")


def _json_data(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"raw_text": path.read_text(encoding="utf-8")}


def _next_output_preview(mode: str) -> str:
    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%SZ")
    return (
        f"Report: {REPORTS_ROOT}\n"
        f"Telemetry: {OUTPUTS_ROOT}/{ts}"
    )


def _tree_nodes_for_run(run_name: str) -> list[dict[str, Any]]:
    files = list(_evidence_files(run_name))
    root: dict[str, Any] = {"id": "root", "label": run_name or "No run selected", "children": []}
    directories: dict[str, dict[str, Any]] = {"": root}
    for file_name in files:
        parts = file_name.split("/")
        parent_key = ""
        for index, part in enumerate(parts):
            key = "/".join(parts[: index + 1])
            is_leaf = index == len(parts) - 1
            if is_leaf:
                directories[parent_key]["children"].append(
                    {"id": file_name, "label": part, "icon": "data_object"}
                )
            elif key not in directories:
                node = {"id": f"dir:{key}", "label": part, "children": []}
                directories[parent_key]["children"].append(node)
                directories[key] = node
            parent_key = key
    return [root]


def _tree_expanded_keys(nodes: list[dict[str, Any]]) -> list[str]:
    expanded: list[str] = []

    def visit(node: dict[str, Any], depth: int) -> None:
        children = node.get("children")
        if children and depth <= 1:
            expanded.append(str(node.get("id", "")))
            for child in children:
                visit(child, depth + 1)

    for node in nodes:
        visit(node, 0)
    return expanded


def _walk_values(data: Any) -> list[tuple[str, Any]]:
    values: list[tuple[str, Any]] = []

    def visit(item: Any, path: str) -> None:
        if isinstance(item, dict):
            for key, value in item.items():
                child_path = f"{path}.{key}" if path else str(key)
                values.append((child_path, value))
                visit(value, child_path)
        elif isinstance(item, list):
            for index, value in enumerate(item):
                visit(value, f"{path}[{index}]")

    visit(data, "")
    return values


def _highlight_markdown(file_name: str, data: Any) -> str:
    highlights: list[str] = []
    for path, value in _walk_values(data):
        value_text = str(value)
        lower_value = value_text.lower()
        if path.endswith(("qname", "queried_domain", "value", "domain")) and any(token in lower_value for token in SUSPICIOUS_DNS_TOKENS):
            highlights.append(f"- Suspicious DNS/domain signal: `{value_text}` at `{path}`")
        if path.endswith("matched_assets") and value:
            highlights.append(f"- Local asset match: `{value_text}` at `{path}`")
        if path.endswith("provenance") and isinstance(value, dict):
            origin = value.get("data_origin", "unknown")
            sample = value.get("sample_data", "unknown")
            highlights.append(f"- Provenance: data origin `{origin}`, sample data `{sample}`")
        if path.endswith("priority") and str(value).lower() in {"critical", "high"}:
            highlights.append(f"- High-priority record at `{path}`: `{value_text}`")
    if not highlights:
        highlights.append("- No obvious suspicious DNS, high-priority, provenance, or asset-match fields detected in this file.")
    return f"### Highlights for `{file_name}`\n" + "\n".join(dict.fromkeys(highlights[:16]))


def _evidence_link_markdown(run_name: str, report_text: str) -> str:
    files = list(_evidence_files(run_name))
    if not files:
        return "No telemetry files found for this run."
    lines = ["### Telemetry Links"]
    report_lower = report_text.lower()
    for file_name in files:
        mentioned = file_name.lower() in report_lower or Path(file_name).name.lower() in report_lower
        marker = "mentioned in report" if mentioned else "available telemetry"
        lines.append(f"- `{file_name}` - {marker}")
    return "\n".join(lines)


def _report_link_files(run_name: str, report_text: str) -> list[str]:
    files = list(_evidence_files(run_name))
    if not files:
        return []

    manifest_path = OUTPUTS_ROOT / run_name / "run_manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            input_files = [str(item) for item in manifest.get("input_files", [])]
            return [file_name for file_name in input_files if file_name in files]
        except json.JSONDecodeError:
            pass

    report_lower = report_text.lower()
    mentioned = [
        file_name
        for file_name in files
        if file_name.lower() in report_lower
        or (len(Path(file_name).parts) == 2 and Path(file_name).name.lower() in report_lower)
    ]
    primary_module_outputs = [
        file_name
        for file_name in files
        if len(Path(file_name).parts) == 2 and Path(file_name).suffix.lower() == ".json"
    ]
    combined = [*mentioned, *primary_module_outputs]
    return list(dict.fromkeys(combined))


def _run_manifest(run_name: str | None) -> dict[str, Any]:
    if not run_name:
        return {}
    manifest_path = OUTPUTS_ROOT / run_name / "run_manifest.json"
    if not manifest_path.exists():
        return {}
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _report_context_files(run_name: str | None, report_text: str) -> tuple[list[str], list[str]]:
    if not run_name:
        return [], []
    files = list(_evidence_files(run_name))
    manifest = _run_manifest(run_name)
    input_files = [str(item) for item in manifest.get("input_files", []) if str(item) in files]
    linked = _report_link_files(run_name, report_text)
    primary = list(dict.fromkeys([*input_files, *linked]))
    supporting = [file_name for file_name in files if file_name not in primary]
    return primary, supporting


def _evidence_empty_message(run_name: str) -> str:
    if not run_name:
        return (
            "No run selected yet. After a run completes, telemetry appears under "
            f"`{OUTPUTS_ROOT}/<run>/<module>/`."
        )
    modules = _module_names_for_run(run_name)
    if not modules:
        return (
            f"`outputs/{run_name}` has no module folders yet. A completed run normally contains folders "
            "such as `dnscap/`, `enumeros/`, `safesniff/`, and `threatsucker/`."
        )
    return f"Module folders found: {', '.join(f'`{name}/`' for name in modules)}"


def _read_evidence_for_display(path: Path) -> tuple[str, Any | None]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json", _json_data(path)
    if suffix == ".jsonl":
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return "json", rows
    return "text", path.read_text(encoding="utf-8")


def _select_options(values: list[str]) -> dict[str, str]:
    return {value: value for value in values}


def _display_options(values: list[str]) -> dict[str, str]:
    friendly = {
        "default": "NGO default",
        "live-conservative": "Conservative assessment",
        "phishing-validation": "Phishing DNS validation",
        "phishing-dns-demo": "Phishing DNS + browser risk",
        "local-llamacpp": "Local llama.cpp",
        "openai-compatible": "OpenAI-compatible API",
    }
    return {value: friendly.get(value, value.replace("-", " ").title()) for value in values}


def _test_suite_path(name: str) -> Path:
    safe_name = name.strip().replace("/", "-") or "validation-suite"
    return TEST_SUITES_ROOT / f"{safe_name}.json"


def _list_test_suites() -> list[str]:
    if not TEST_SUITES_ROOT.exists():
        return []
    return sorted(path.stem for path in TEST_SUITES_ROOT.glob("*.json"))


def _load_test_suite(name: str) -> dict[str, Any]:
    path = _test_suite_path(name)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _save_test_suite(name: str, data: dict[str, Any]) -> Path:
    TEST_SUITES_ROOT.mkdir(parents=True, exist_ok=True)
    path = _test_suite_path(name)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _module_test_options(module_name: str) -> dict[str, str]:
    return {str(key): str(value) for key, value in _module_validation_capability(module_name)["conditions"].items()}


def _normalise_validation_choice(value: str | None) -> str:
    legacy = {
        "disabled_for_run": "off",
        "normal_baseline": "nominal",
        "clean_dns_log_import": "nominal",
        "normal_asset_inventory": "nominal",
        "target_detection_only_baseline": "nominal",
        "normal_correlation": "nominal",
        "suspicious_dns_log_import": "actionable_issue",
        "threat_intel_correlation_positive": "actionable_issue",
        "outdated_browser_signal": "weak_issue",
        "active_scan_fixture": "weak_issue",
    }
    raw = value or "nominal"
    return legacy.get(raw, raw)


def _module_scope_options(module_name: str) -> dict[str, str]:
    return {str(key): str(value) for key, value in _module_validation_capability(module_name)["scopes"].items()}


def _default_module_scopes() -> dict[str, str]:
    return {
        row["module"]: str(_module_validation_capability(row["module"]).get("default_scope") or "module_default")
        for row in _module_rows()
        if row["status"] == "detected"
    }


def _module_scope_value(module_name: str, module_scopes: dict[str, str] | None) -> str:
    options = _module_scope_options(module_name)
    selected = (module_scopes or {}).get(module_name)
    return selected if selected in options else next(iter(options))


def _slug_for_path(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in value.strip().lower())
    return cleaned.strip("_") or "default"


def _module_validation_telemetry_dir(module_name: str) -> Path:
    return MODULES_ROOT / module_name / "validation_telemetry"


def _module_validation_telemetry_path(module_name: str, condition: str, scope: str) -> Path:
    condition_slug = _slug_for_path(_normalise_validation_choice(condition))
    scope_slug = _slug_for_path(scope)
    return _module_validation_telemetry_dir(module_name) / f"{condition_slug}__{scope_slug}.json"


def _normalise_telemetry_document(module_name: str, condition: str, scope: str, data: Any) -> dict[str, Any]:
    if isinstance(data, dict) and isinstance(data.get("files"), list):
        document = dict(data)
        document.setdefault("schema_version", 1)
        document.setdefault("module", module_name)
        document.setdefault("condition", _normalise_validation_choice(condition))
        document.setdefault("scope", scope)
        return document
    if isinstance(data, list):
        return {
            "schema_version": 1,
            "module": module_name,
            "condition": _normalise_validation_choice(condition),
            "scope": scope,
            "files": data,
        }
    return {
        "schema_version": 1,
        "module": module_name,
        "condition": _normalise_validation_choice(condition),
        "scope": scope,
        "files": [],
    }


def _write_module_validation_telemetry(module_name: str, condition: str, scope: str, data: Any) -> Path:
    document = _normalise_telemetry_document(module_name, condition, scope, data)
    target = _module_validation_telemetry_path(module_name, condition, scope)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, indent=2, sort_keys=False), encoding="utf-8")
    return target


def _module_validation_telemetry_document(module_name: str, condition: str, scope: str, generate_missing: bool = True) -> dict[str, Any]:
    path = _module_validation_telemetry_path(module_name, condition, scope)
    if path.exists():
        try:
            return _normalise_telemetry_document(module_name, condition, scope, json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            return _normalise_telemetry_document(module_name, condition, scope, {"files": []})
    if not generate_missing:
        return _normalise_telemetry_document(module_name, condition, scope, {"files": []})
    runner = _module_runner_instance(module_name)
    generated: list[dict[str, Any]] = []
    if runner is not None and hasattr(runner, "generate_validation_evidence"):
        payload = runner.generate_validation_evidence(condition=_normalise_validation_choice(condition), scope=scope)
        if isinstance(payload, list):
            generated = [item for item in payload if isinstance(item, dict)]
    document = _normalise_telemetry_document(module_name, condition, scope, {"files": generated})
    _write_module_validation_telemetry(module_name, condition, scope, document)
    return document


def _module_validation_telemetry_display_path(module_name: str, condition: str, scope: str) -> str:
    return str(_module_validation_telemetry_path(module_name, condition, scope).relative_to(PROJECT_ROOT))


def _module_description_markdown(module_name: str) -> str:
    descriptions = {
        "dnscap": (
            "Imports historical DNS query logs and summarises which domains were resolved by each observed device. "
            "Useful for spotting phishing lookalikes, credential-theft domains, invoice/payment lures, and activity from non-local devices visible to DNS infrastructure. "
            "DNS alone is not proof of compromise; it is a timeline and triage signal."
        ),
        "enumeros": (
            "Collects or imports asset inventory: operating system, browser versions, software versions, patch/support status, and local host facts. "
            "It can represent the scan-assess machine or another supplied/observed endpoint. "
            "Useful for finding unsupported OS versions, outdated browsers, risky endpoint configuration, and whether vulnerable software matches threat intelligence."
        ),
        "safesniff": (
            "Performs permissioned safe network discovery and TCP service enumeration against selected targets. "
            "Its findings are observed network devices rather than local host inventory. "
            "It can flag exposed admin surfaces, SMB/RDP/web services, likely device roles, and where encryption should be checked, such as HTTPS/TLS versus plaintext HTTP or unencrypted management interfaces."
        ),
        "threatsucker": (
            "Collects and reduces threat-intelligence feeds, then correlates indicators and vulnerabilities against local context such as domains, brands, software, and assets. "
            "Useful for filtering noisy feeds into explainable matches, allowlisting expected domains, and preserving provenance for why an indicator is relevant."
        ),
        "sitechecker": (
            "Runs a low-impact owner-authorized exposure and hardening check against one configured website. "
            "It checks HTTPS posture, security headers, cookie flags, common exposed paths such as .env or .git metadata, login/form exposure, technology markers, and simple legacy-version heuristics. "
            "It is designed for the organisation's own website and writes its findings as module JSON telemetry for scan-assess."
        ),
        "example_module": (
            "Minimal example runner used to prove the module interface works. "
            "It is disabled by default because its output is not operational security telemetry."
        ),
    }
    return descriptions.get(
        module_name,
        "Detected module. It contributes JSON telemetry to scan-assess when enabled.",
    )


def _default_validation_module_tests() -> dict[str, str]:
    return {
        row["module"]: _normalise_validation_choice(str(_module_validation_capability(row["module"]).get("default_condition") or "nominal"))
        for row in _module_rows()
        if row["status"] == "detected"
    }


def _background_evidence_from_run(run_name: str | None) -> list[dict[str, Any]]:
    if not run_name:
        return []
    run_dir = OUTPUTS_ROOT / run_name
    if not run_dir.exists():
        return []

    manifest = _run_manifest(run_name)
    input_files = [str(item) for item in manifest.get("input_files", [])]
    if not input_files:
        input_files = [
            file_name
            for file_name in _evidence_files(run_name)
            if len(Path(file_name).parts) == 2 and Path(file_name).suffix.lower() == ".json"
        ]

    files: list[dict[str, Any]] = []
    for file_name in input_files[:8]:
        path = run_dir / file_name
        if not path.exists() or path.suffix.lower() != ".json":
            continue
        data = _json_data(path)
        files.append({"filename": f"historical/{file_name}", "file_data": data})
    return files


def _generated_background_noise(noise_level: int) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for row in _module_rows():
        if row["status"] != "detected":
            continue
        runner = _module_runner_instance(row["module"])
        if runner is None or not hasattr(runner, "generate_validation_noise"):
            continue
        generated = runner.generate_validation_noise(noise_level=noise_level)
        if isinstance(generated, list):
            module_files = [item for item in generated if isinstance(item, dict)]
            if module_files:
                _write_module_validation_telemetry(
                    row["module"],
                    f"background_{int(noise_level)}",
                    "module_default",
                    {
                        "schema_version": 1,
                        "module": row["module"],
                        "condition": f"background_{int(noise_level)}",
                        "scope": "module_default",
                        "purpose": "background validation telemetry",
                        "files": module_files,
                    },
                )
                files.extend(module_files)
    return files


def _selected_positive_summary(module_tests: dict[str, str]) -> list[str]:
    labels: list[str] = []
    for module_name, selected in module_tests.items():
        selected = _normalise_validation_choice(selected)
        if selected in {"off", "nominal"}:
            continue
        labels.append(f"`{module_name}`: {_module_test_options(module_name).get(selected, selected)}")
    return labels


def _legacy_prompt_developer_evidence(
    module_tests: dict[str, str],
    background_run_name: str | None = None,
    module_scopes: dict[str, str] | None = None,
    background_noise: int = 0,
) -> str:
    """Build the editable telemetry payload without revealing validation intent to the LLM."""
    dnscap_mode = _normalise_validation_choice(module_tests.get("dnscap", "actionable_issue"))
    threatsucker_mode = _normalise_validation_choice(module_tests.get("threatsucker", "actionable_issue"))
    enumeros_mode = _normalise_validation_choice(module_tests.get("enumeros", "nominal"))
    safesniff_mode = _normalise_validation_choice(module_tests.get("safesniff", "nominal"))
    dnscap_scope = _module_scope_value("dnscap", module_scopes)
    enumeros_scope = _module_scope_value("enumeros", module_scopes)
    safesniff_scope = _module_scope_value("safesniff", module_scopes)

    files: list[dict[str, Any]] = _background_evidence_from_run(background_run_name)
    files.extend(_generated_background_noise(background_noise))

    if dnscap_mode != "off":
        if dnscap_scope == "observed_device":
            dns_host = "finance-tablet-02"
            dns_context = {
                "device_scope": "observed_non_local_device",
                "observed_by": "office-dns-resolver-01",
                "is_local_host": False,
                "reporting_hint": "This DNS telemetry came from a network-observed device, not the machine running scan-assess.",
            }
        else:
            dns_host = "office-laptop-01"
            dns_context = {
                "device_scope": "local_device",
                "observed_by": "scan-assess host",
                "is_local_host": True,
                "reporting_hint": "This DNS telemetry is for the local machine running scan-assess.",
            }
        dns_payload: dict[str, Any] = {
            "module": "dnscap",
            "provenance": {
                "data_origin": "operator_supplied",
                "sample_data": False,
                "collection_method": "historical_dns_log_import",
            },
            "host": dns_host,
            "asset_context": dns_context,
            "observed_queries": ["microsoft.com", "office.com", "google.com", "docusign.com"],
        }
        if dnscap_mode == "actionable_issue":
            dns_payload["suspicious_queries"] = [
                {"qname": "login-micros0ft-security.com", "reason": "Microsoft lookalike login domain"},
                {"qname": "secure-sharepoint-document-login.com", "reason": "document-sharing login lure"},
                {"qname": "paypal-invoice-confirmation-portal.com", "reason": "payment/invoice lure"},
            ]
        elif dnscap_mode == "weak_issue":
            dns_payload["suspicious_queries"] = [
                {"qname": "login-office365-support.example", "reason": "login-themed domain outside known allowlist"}
            ]
            dns_payload["telemetry_limitations"] = [
                "Single low-volume DNS lookup only.",
                "No threat-intel correlation or confirmed browser visit in this telemetry.",
            ]
        else:
            dns_payload["suspicious_queries"] = []
        files.append({"filename": "dnscap/dnscap_summary.json", "file_data": dns_payload})

    if enumeros_mode != "off":
        if enumeros_mode == "actionable_issue":
            inventory_host = "accounts-workstation-07" if enumeros_scope == "observed_device" else "office-laptop-01"
            enumeros_payload = {
                "module": "enumeros",
                "provenance": {"data_origin": "local_inventory", "sample_data": False},
                "hostname": inventory_host,
                "asset_context": {
                    "device_scope": "observed_non_local_device" if enumeros_scope == "observed_device" else "local_device",
                    "is_local_host": enumeros_scope != "observed_device",
                    "inventory_method": "imported_or_agent_supplied_inventory" if enumeros_scope == "observed_device" else "local_inventory",
                    "reporting_hint": "Distinguish this asset from the scan-assess host when writing findings.",
                },
                "os": {
                    "platform": "windows",
                    "product_name": "Windows 11",
                    "display_version": "21H2",
                    "build_number": 22000,
                    "support_status": "unsupported_or_out_of_servicing",
                },
                "browsers": {"edge": "145.0.3720.10", "chrome": "123.0.6312.86"},
                "version_status": {
                    "items": [
                        {"name": "os", "installed": "21H2", "latest": "25H2", "status": "outdated", "source": "Windows release policy"},
                        {"name": "chrome", "installed": "123.0.6312.86", "latest": "149.0.7827.29", "status": "outdated", "source": "Chrome Version History API"},
                    ]
                },
                "network_discovery": {
                    "method": "tcp_connect",
                    "local_ip": "10.40.12.44",
                    "assumed_subnet": "10.40.12.0/24",
                    "hosts": [{"ip": "10.40.12.44", "open_ports": [{"port": 445, "status": "open"}, {"port": 3389, "status": "open"}]}],
                },
                "summary": {"overall": "critical", "outdated_count": 2, "open_service_count": 2},
            }
        else:
            browser_version = "123.0.6312.86" if enumeros_mode == "weak_issue" else "149.0.7827.29"
            inventory_host = "volunteer-laptop-03" if enumeros_scope == "observed_device" else "office-laptop-01"
            enumeros_payload = {
                "module": "enumeros",
                "provenance": {"data_origin": "local_inventory", "sample_data": False},
                "hostname": inventory_host,
                "asset_context": {
                    "device_scope": "observed_non_local_device" if enumeros_scope == "observed_device" else "local_device",
                    "is_local_host": enumeros_scope != "observed_device",
                    "inventory_method": "imported_or_agent_supplied_inventory" if enumeros_scope == "observed_device" else "local_inventory",
                    "reporting_hint": "Distinguish this asset from the scan-assess host when writing findings.",
                },
                "os": {"platform": "macos", "product_name": "macOS", "product_version": "26.5", "support_status": "current"},
                "browsers": {"chrome": browser_version, "safari": "26.5"},
                "version_status": {
                    "items": [
                        {"name": "os", "installed": "26.5", "latest": "26.5", "status": "current", "source": "OS vendor release policy"},
                        {
                            "name": "chrome",
                            "installed": browser_version,
                            "latest": "149.0.7827.29",
                            "status": "outdated" if enumeros_mode == "weak_issue" else "current",
                            "source": "Chrome Version History API",
                        },
                    ]
                },
                "summary": {"overall": "warnings" if enumeros_mode == "weak_issue" else "ok", "outdated_count": 1 if enumeros_mode == "weak_issue" else 0, "open_service_count": 0},
            }
        files.append(
            {
                "filename": "enumeros/enumeros.json",
                "file_data": enumeros_payload,
            }
        )

    if threatsucker_mode != "off":
        correlation_payload: dict[str, Any] = {
            "module": "threatsucker",
            "provenance": {
                "data_origin": "operator_supplied_correlation",
                "sample_data": False,
                "correlation_layer": True,
            },
            "dns_matches": [],
            "relevant_vulnerabilities": [],
        }
        if threatsucker_mode == "actionable_issue":
            correlation_payload["dns_matches"] = [
                {
                    "indicator": "login-micros0ft-security.com",
                    "threat_type": "phishing",
                    "priority": "critical",
                    "matched_assets": ["office-laptop-01"],
                }
            ]
            correlation_payload["relevant_vulnerabilities"] = [
                {
                    "cve": "CVE-2025-6554",
                    "product": "Chrome",
                    "affected_version": "123.0.6312.86",
                    "matched_assets": ["office-laptop-01:chrome"],
                    "priority": "critical",
                }
            ]
        elif threatsucker_mode == "weak_issue":
            correlation_payload["relevant_vulnerabilities"] = [
                {
                    "cve": "CVE-2025-6554",
                    "product": "Chrome",
                    "affected_version": "unknown",
                    "matched_assets": [],
                    "priority": "medium",
                    "limitation": "Relevant exploited browser vulnerability exists, but no local affected version match is present.",
                }
            ]
        files.append({"filename": "threatsucker/threatsucker_correlation.json", "file_data": correlation_payload})

    if safesniff_mode != "off":
        if safesniff_mode == "actionable_issue":
            safesniff_payload = {
                "module": "safesniff",
                "tool": "safesniff",
                "mode": "permissioned_safe_tcp_enumeration",
                "profile": "thorough",
                "provenance": {"active_network_scan": True, "total_tcp_connect_attempts_planned": 28448, "sample_data": False},
                "target": "10.40.12.0/24",
                "asset_context": {
                    "device_scope": safesniff_scope,
                    "is_local_host": False,
                    "reporting_hint": "SafeSniff findings are observed network devices and services, not local host inventory.",
                },
                "device_inventory": {
                    "observed_device_count": 4,
                    "active_with_open_services": 3,
                    "devices": [
                        {
                            "ip": "10.40.12.44",
                            "label": "accounts-workstation-07",
                            "likely_role": "windows_workstation_or_file_sharing_host",
                            "exposure_level": "high",
                            "open_ports": [135, 139, 445, 3389],
                            "security_review_priority": "high",
                            "risk_tags": ["file_sharing_or_rpc_surface", "remote_admin_surface"],
                        },
                        {
                            "ip": "10.40.12.20",
                            "label": "nas-finance",
                            "likely_role": "file_server_or_nas",
                            "exposure_level": "high",
                            "open_ports": [445, 5000, 5001],
                            "security_review_priority": "high",
                            "risk_tags": ["file_sharing_or_rpc_surface", "web_admin_or_app_surface"],
                        },
                    ],
                },
                "hosts": [
                    {
                        "ip": "10.40.12.44",
                        "services": [
                            {"port": 445, "service": "smb", "severity": "high", "category": "file_sharing_or_rpc", "remediation": "Restrict SMB to trusted hosts and verify patch level."},
                            {"port": 3389, "service": "rdp", "severity": "high", "category": "remote_admin", "remediation": "Disable or restrict RDP; require VPN/MFA."},
                        ],
                    }
                ],
                "summary": {"overall": "critical", "high_count": 2, "medium_count": 1, "open_service_count": 7},
            }
        elif safesniff_mode == "weak_issue":
            safesniff_payload = {
                "module": "safesniff",
                "tool": "safesniff",
                "mode": "permissioned_safe_tcp_enumeration",
                "provenance": {"active_network_scan": True, "total_tcp_connect_attempts_planned": 256, "sample_data": False},
                "target": "198.51.100.0/24",
                "asset_context": {
                    "device_scope": safesniff_scope,
                    "is_local_host": False,
                    "reporting_hint": "SafeSniff findings are observed network devices and services, not local host inventory.",
                },
                "device_inventory": {
                    "observed_device_count": 3,
                    "active_with_open_services": 1,
                    "devices": [
                        {
                            "ip": "198.51.100.1",
                            "label": "gateway",
                            "likely_role": "router_or_gateway",
                            "exposure_level": "medium",
                            "open_ports": [80, 443],
                            "security_review_priority": "medium",
                            "risk_tags": ["web_admin_or_app_surface"],
                        }
                    ],
                },
                "summary": {"overall": "warnings", "high_count": 0, "medium_count": 1, "open_service_count": 2},
            }
        else:
            safesniff_payload = {
                "module": "safesniff",
                "mode": "target_detection_only",
                "provenance": {"active_network_scan": False, "total_tcp_connect_attempts_planned": 0},
                "asset_context": {
                    "device_scope": safesniff_scope,
                    "is_local_host": False,
                    "reporting_hint": "Target detection does not prove services are open.",
                },
                "note": "Target was selected, but no TCP service scan was run.",
            }
        files.append({"filename": "safesniff/safesniff.json", "file_data": safesniff_payload})

    if _normalise_validation_choice(module_tests.get("example_module", "nominal")) != "off":
        files.append(
            {
                "filename": "example_module/example_output.json",
                "file_data": {
                    "module": "example_module",
                    "provenance": {"data_origin": "operator_supplied", "sample_data": False},
                    "status": "no actionable findings",
                },
            }
        )

    return json.dumps({"files": files}, indent=2)


def _module_validation_warning(module_name: str) -> str:
    capability = _module_validation_capability(module_name)
    conditions = capability.get("conditions") if isinstance(capability.get("conditions"), dict) else {}
    if not capability.get("supports_true_positive") or "actionable_issue" not in conditions:
        return "Light warning: this module does not expose a high-confidence positive telemetry option yet."
    return str(capability.get("warning") or "")


def _module_generated_validation_evidence(
    module_name: str,
    condition: str,
    module_scopes: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    runner = _module_runner_instance(module_name)
    if runner is None or not hasattr(runner, "generate_validation_evidence"):
        return []
    options = _module_test_options(module_name)
    selected = _normalise_validation_choice(condition)
    if selected not in options:
        selected = "nominal" if "nominal" in options else next(iter(options))
    scope = _module_scope_value(module_name, module_scopes)
    document = _module_validation_telemetry_document(module_name, selected, scope, generate_missing=True)
    files = document.get("files")
    return [item for item in files if isinstance(item, dict)] if isinstance(files, list) else []


def _prompt_developer_evidence(
    module_tests: dict[str, str],
    background_run_name: str | None = None,
    module_scopes: dict[str, str] | None = None,
    background_noise: int = 0,
) -> str:
    """Build the editable telemetry payload from module-owned validation generators."""
    files: list[dict[str, Any]] = _background_evidence_from_run(background_run_name)
    files.extend(_generated_background_noise(background_noise))
    for row in _module_rows():
        if row["status"] != "detected":
            continue
        module_name = row["module"]
        capability = _module_validation_capability(module_name)
        selected = _normalise_validation_choice(
            module_tests.get(module_name, str(capability.get("default_condition") or "nominal"))
        )
        files.extend(_module_generated_validation_evidence(module_name, selected, module_scopes))
    return json.dumps({"files": files}, indent=2)


@ui.page("/")
def main_page() -> None:
    ui.colors(primary="#256f5b", secondary="#384152", accent="#b7791f", positive="#2f855a", warning="#b7791f", negative="#b83232")
    dark_mode = ui.dark_mode(value=True)
    ui.add_head_html(
        """
        <style>
          html, body, #q-app { height: 100%; overflow: hidden; }
          *, *::before, *::after { box-sizing: border-box; }
          body { background: #f6f7f4; color: #1f2933; }
          body.body--dark { background: #0f1416; color: #e7edf0; }
          .sa-shell { height: 100vh; width: 100vw; max-width: none; margin: 0; padding: 8px 14px; overflow: hidden; box-sizing: border-box; display: grid; grid-template-rows: 36px minmax(0, 1fr); gap: 8px; }
          .sa-header { height: 36px; min-height: 36px; }
          .sa-header-actions { display: flex; align-items: center; gap: 8px; }
          .sa-main { width: 100%; height: 100%; max-height: 100%; min-height: 0; min-width: 0; overflow: hidden; display: grid; grid-template-columns: minmax(0, 1fr); gap: 12px; }
          .sa-sidebar { display: none; height: 100%; min-height: 0; overflow: auto; }
          .sa-sidebar .q-expansion-item { border: 1px solid #d9ded8; border-radius: 8px; background: #fff; }
          .sa-sidebar .q-expansion-item__container { border-radius: 8px; }
          .sa-sidebar .q-item { min-height: 42px; padding: 6px 10px; }
          .sa-workspace { height: 100%; max-height: 100%; min-height: 0; min-width: 0; overflow: hidden; display: grid; grid-template-rows: 54px minmax(0, 1fr); gap: 10px; }
          .sa-panels { height: 100%; min-height: 0; overflow: hidden; }
          .sa-nav { height: 54px; min-height: 54px; border: 1px solid #d9ded8; border-radius: 8px; background: #ffffff; }
          .sa-nav .q-tab__label { text-transform: none; font-size: 14px; letter-spacing: 0; }
          .sa-nav .q-tab { min-height: 52px; padding: 6px 18px; }
          .sa-page { height: 100%; min-height: 0; overflow: auto; }
          .sa-reports-page { display: grid !important; grid-template-rows: auto auto auto minmax(0, 1fr); gap: 6px; overflow: hidden; padding-bottom: 12px; }
          .sa-page .q-field, .sa-page .q-btn { min-width: 0; }
          .sa-page > .q-row, .sa-page > .nicegui-row { min-height: 0; }
          .sa-scroll { height: calc(100vh - 195px); overflow: auto; min-height: 0; }
          .sa-report-grid { display: grid; grid-template-columns: minmax(0, 3fr) minmax(340px, 2fr); gap: 12px; min-height: 0; height: 100%; margin-bottom: 0; }
          .sa-report-view { height: 100%; overflow: auto; min-height: 0; }
          .sa-report-view h1 { font-size: 28px; line-height: 1.2; margin: 0 0 10px; }
          .sa-report-view h2 { font-size: 22px; line-height: 1.25; margin: 18px 0 8px; }
          .sa-report-view h3 { font-size: 17px; line-height: 1.25; margin: 14px 0 6px; }
          .sa-report-view p, .sa-report-view li { font-size: 15px; line-height: 1.45; }
          .sa-report-context { height: 100%; overflow: auto; min-height: 0; }
          .sa-context-button .q-btn__content { justify-content: flex-start; text-align: left; white-space: normal; }
          .sa-evidence-page { display: grid !important; grid-template-rows: auto auto minmax(0, 1fr); gap: 8px; overflow: hidden; padding-bottom: 12px; }
          .sa-evidence-layout { display: grid; grid-template-columns: minmax(320px, .9fr) minmax(0, 1.6fr); gap: 12px; height: 100%; min-height: 0; overflow: hidden; }
          .sa-evidence-left { height: 100%; min-height: 0; overflow: hidden; display: grid; grid-template-rows: auto minmax(0, 1fr) auto; gap: 8px; }
          .sa-evidence-right { height: 100%; min-height: 0; overflow: hidden; display: grid; grid-template-rows: auto minmax(0, 86px) minmax(0, 1fr); gap: 8px; }
          .sa-evidence-tree { height: 100%; min-height: 0; overflow: auto; }
          .sa-evidence-highlight { max-height: 86px; overflow: auto; }
          .sa-evidence-highlight h3 { font-size: 15px; line-height: 1.2; margin: 0 0 4px; }
          .sa-evidence-highlight code { white-space: normal; overflow-wrap: anywhere; }
          .sa-evidence-json { height: 100%; min-height: 0; overflow: auto; }
          .sa-evidence-text { height: 100% !important; min-height: 0 !important; }
          .sa-evidence-text .q-field__control { height: 100% !important; min-height: 0 !important; }
          .sa-evidence-text textarea { height: 100% !important; max-height: none !important; resize: none; overflow: auto; }
          .sa-prompt-dev-page { display: grid !important; grid-template-rows: auto auto minmax(0, 270px) minmax(0, 1fr); gap: 8px; overflow: hidden; padding-bottom: 12px; }
          .sa-prompt-dev-main { display: grid; grid-template-columns: minmax(240px, 0.45fr) minmax(520px, 1.7fr) minmax(300px, 0.65fr); gap: 10px; min-height: 0; height: 100%; overflow: hidden; }
          .sa-evidence-generator { height: 100%; min-height: 0; overflow: auto; }
          .sa-positive-summary { max-height: 70px; overflow: auto; }
          .sa-prompt-actions { align-content: start; }
          .sa-validation-output { height: 100%; min-height: 0; overflow: auto; }
          .sa-validation-output-card { height: 100%; min-height: 0; overflow: hidden; display: grid; grid-template-rows: auto minmax(0, 1fr); gap: 6px; }
          .sa-validation-output h1 { font-size: 26px; line-height: 1.2; margin: 0 0 10px; }
          .sa-validation-output h2 { font-size: 21px; line-height: 1.25; margin: 16px 0 8px; }
          .sa-validation-output p, .sa-validation-output li { font-size: 15px; line-height: 1.45; }
          .sa-scan-card { min-height: 0; overflow: hidden; padding-top: 8px !important; padding-bottom: 8px !important; gap: 4px !important; }
          .sa-scan-card .q-expansion-item .q-item { min-height: 32px; padding: 2px 8px; }
          .sa-scan-row { display: grid; grid-template-columns: minmax(300px, 1.5fr) minmax(210px, .9fr) minmax(260px, 1fr) 190px; gap: 10px; align-items: end; min-width: 0; }
          .sa-scan-row > * { min-width: 0; }
          .sa-dnscap-row { display: grid; grid-template-columns: minmax(280px, 1.4fr) minmax(160px, .45fr) minmax(160px, .55fr) minmax(160px, .55fr); gap: 8px; align-items: end; min-width: 0; }
          .sa-dnscap-row > * { min-width: 0; }
          .sa-scan-meta { font-size: 12px; line-height: 1.25; }
          .sa-scan-meta p { margin: 0; }
          .sa-scan-output { font-size: 12px; line-height: 1.25; max-height: 52px; overflow: auto; }
          .sa-scan-output p { margin: 0; }
          .sa-run-log { height: 86px !important; min-height: 86px !important; display: none; }
          .sa-run-log .q-field__control { height: 86px !important; min-height: 86px !important; }
          .sa-run-log textarea { height: 58px !important; max-height: 58px !important; resize: none; }
          .sa-setup-grid { display: grid; grid-template-columns: minmax(300px, 420px) minmax(0, 1fr); gap: 12px; min-height: 0; height: calc(100vh - 155px); }
          .sa-module-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; align-content: start; }
          .sa-generator-page { display: grid !important; grid-template-rows: auto minmax(0, 1fr); gap: 10px; overflow: hidden; padding-bottom: 12px; }
          .sa-generator-layout { display: grid; grid-template-columns: minmax(340px, 0.75fr) minmax(520px, 1.55fr); gap: 12px; min-height: 0; height: 100%; overflow: hidden; }
          .sa-generator-modules { min-height: 0; overflow: auto; padding-right: 4px; }
          .sa-generator-card { border-left: 3px solid #2f7d64; }
          .sa-generator-right { min-height: 0; height: 100%; overflow: hidden; display: grid !important; grid-template-rows: min-content min-content min-content minmax(0, 1fr); gap: 10px; align-content: stretch; }
          .sa-generator-preview { width: 100% !important; min-width: 0 !important; min-height: 0 !important; height: 100% !important; background: #f8faf8; border-radius: 8px; }
          .sa-generator-preview .q-field__control { height: 100% !important; min-height: 0 !important; background: #f8faf8; }
          .sa-generator-preview textarea { height: 100% !important; max-height: none !important; resize: none; overflow: auto; white-space: pre; font-size: 15px !important; line-height: 1.48 !important; color: #172126; caret-color: #256f5b; tab-size: 2; }
          .sa-generator-status { min-height: 0; max-height: 34px; overflow: auto; margin: 0; }
          .sa-generator-status p { margin: 0; }
          .sa-injector-panel { border-left: 3px solid #8aa7ff; }
          .sa-compact-scroll { max-height: 230px; overflow: auto; min-height: 0; }
          .sa-compact-scroll h3 { font-size: 18px; line-height: 1.2; margin: 0 0 6px; }
          .sa-compact-scroll p, .sa-compact-scroll li { margin: 2px 0; }
          .sa-module-list { flex: 1 1 auto; min-height: 0; overflow: auto; }
          .sa-band { background: #ffffff; border: 1px solid #d9ded8; border-radius: 8px; }
          .sa-muted { color: #5f6b63; }
          body.body--dark .sa-band, body.body--dark .sa-nav { background: #151c1f; border-color: #2f3b3f; color: #e7edf0; }
          body.body--dark .sa-muted { color: #a7b4b8; }
          body.body--dark .q-field__control { background: #101719; color: #e7edf0; }
          body.body--dark .q-field__native, body.body--dark .q-field__input, body.body--dark textarea { color: #e7edf0; }
          body.body--dark .q-field__label { color: #a7b4b8; }
          body.body--dark .nicegui-markdown code { background: #0d1214; color: #dce8eb; }
          body.body--dark .q-menu { background: #151c1f; color: #e7edf0; }
          body.body--dark .sa-generator-preview, body.body--dark .sa-generator-preview .q-field__control { background: #0b1113; border-color: #3d4b50; }
          body.body--dark .sa-generator-preview textarea { color: #f0f7fa; text-decoration-color: transparent; }
          .sa-code textarea { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13px; line-height: 1.42; }
          .sa-code .q-field__control { min-height: 0; }
          .sa-small-field .q-field__control { min-height: 42px; height: 42px; }
          .sa-small-field .q-field__label { font-size: 12px; }
          .sa-page textarea { max-height: 180px; }
          .sa-prompt-box { width: calc(50% - 6px) !important; height: 270px !important; min-height: 270px !important; }
          .sa-prompt-box .q-field__control { height: 270px !important; min-height: 270px !important; }
          .sa-prompt-box textarea { height: 238px !important; max-height: 238px !important; resize: none; overflow-y: scroll !important; overflow-x: auto !important; pointer-events: auto !important; }
          .sa-evidence-editor { height: 100% !important; min-height: 0 !important; }
          .sa-evidence-editor .q-field__control { height: 100% !important; min-height: 0 !important; }
          .sa-evidence-editor textarea { height: 100% !important; max-height: none !important; resize: none; overflow: auto; }
          .sa-controls-dialog-card { width: min(1480px, calc(100vw - 56px)) !important; max-width: calc(100vw - 56px) !important; height: min(900px, calc(100vh - 56px)) !important; max-height: calc(100vh - 56px) !important; display: grid !important; grid-template-rows: auto minmax(0, 1fr); overflow: hidden; }
          .sa-controls-frame { width: 100%; height: 100%; min-height: 0; border: 1px solid #d9ded8; border-radius: 8px; background: #ffffff; }
          body.body--dark .sa-controls-frame { border-color: #2f3b3f; background: #0b1113; }
          .sa-workspace .q-tab-panel { height: 100%; overflow: hidden; padding: 0; }
          .sa-workspace .q-tab-panels { height: 100%; min-height: 0; background: transparent; }
        </style>
        """
    )

    state: dict[str, Any] = {
        "current_profile": load_prompt_profile("default"),
        "module_tests": _default_validation_module_tests(),
        "module_scopes": _default_module_scopes(),
        "active_test_suite": "full-validation" if "full-validation" in _list_test_suites() else "",
        "background_noise": 30,
        "module_enabled": {
            row["module"]: row["module"] != "example_module"
            for row in _module_rows()
            if row["status"] == "detected"
        },
        "running": False,
        "demo_run_button": None,
        "generator_selected_module": next((row["module"] for row in _module_rows() if row["status"] == "detected"), ""),
        "active_llm_profile": "local-llamacpp" if "local-llamacpp" in list_llm_profiles() else next(iter(list_llm_profiles()), None),
        "settings_processes": {},
        "report_token_cap_enabled": True,
        "report_token_cap": 1200,
        "dnscap_log_root": _default_dnscap_log_root(),
        "dnscap_period": _default_dnscap_period(),
        "dnscap_start": str(load_module_runtime_config(MODULES_ROOT / "dnscap").get("start") or ""),
        "dnscap_end": str(load_module_runtime_config(MODULES_ROOT / "dnscap").get("end") or ""),
        "dnscap_use_last_run_marker": bool(
            load_module_runtime_config(MODULES_ROOT / "dnscap").get(
                "update_last_run_marker",
                load_module_runtime_config(MODULES_ROOT / "dnscap").get("use_last_run_marker", False),
            )
        ),
        "dnscap_last_run_utc": str(load_module_runtime_config(MODULES_ROOT / "dnscap").get("last_run_utc") or ""),
    }

    with ui.column().classes("sa-shell"):
        with ui.row().classes("w-full items-center justify-between sa-header"):
            with ui.column().classes("gap-0"):
                ui.label("scan-assess workbench").classes("text-2xl font-bold")
            with ui.element("div").classes("sa-header-actions"):
                dark_toggle = ui.button("Light mode", icon="light_mode").props("outline dense")
                ui.badge("GUI branch", color="primary").classes("text-sm")

                def toggle_dark_mode() -> None:
                    dark_mode.value = not dark_mode.value
                    dark_toggle.text = "Light mode" if dark_mode.value else "Dark mode"
                    dark_toggle.props(f"icon={'light_mode' if dark_mode.value else 'dark_mode'}")

                dark_toggle.on("click", lambda event: toggle_dark_mode())

        with ui.element("div").classes("sa-main"):
            with ui.column().classes("sa-band p-3 gap-2 sa-sidebar"):
                ui.label("Run Controls").classes("text-lg font-semibold")
                ui.label("Prompt checks and assessments use the selected prompt, model, and enabled modules.").classes("sa-muted text-sm")
                with ui.expansion("Run setup", icon="tune", value=False).classes("w-full"):
                    with ui.column().classes("w-full gap-2 p-2"):
                        prompt_select = ui.select(
                            _display_options(list_prompt_profiles()),
                            label="Prompt profile",
                            value="default",
                        ).classes("w-full sa-small-field")
                        llm_select = ui.select(
                            _display_options(list_llm_profiles()),
                            label="LLM profile",
                            value="local-llamacpp" if "local-llamacpp" in list_llm_profiles() else next(iter(list_llm_profiles()), None),
                        ).classes("w-full sa-small-field")
                        llm_name = ui.input("Profile name").classes("w-full sa-small-field")
                        llm_model = ui.input("Model").classes("w-full sa-small-field")
                        llm_base_url = ui.input("Base URL").classes("w-full sa-small-field")
                        llm_api_key_env = ui.input("API key env var").classes("w-full sa-small-field")
                        llm_description = ui.input("Description").classes("w-full sa-small-field")
                        llm_context_size = ui.number("Context size", value=32768, min=1024, step=1024).classes("w-full sa-small-field")
                        llm_local_model_path = ui.input("Local model path").classes("w-full sa-small-field")
                        llm_local_server_binary = ui.input("Server binary").classes("w-full sa-small-field")
                        with ui.row().classes("w-full gap-2"):
                            llm_local_server_host = ui.input("Host").classes("grow sa-small-field")
                            llm_local_server_port = ui.number("Port", value=8033, min=1, max=65535, step=1).classes("grow sa-small-field")
                        save_llm_button = ui.button("Save LLM Profile", icon="save").props("outline dense").classes("w-full")
                        llm_status = ui.markdown("").classes("sa-muted")
                        with ui.row().classes("w-full gap-2"):
                            ui.button("NGO Default", icon="lock", on_click=lambda: prompt_select.set_value("default")).props("outline dense").classes("grow")
                            ui.button("Prompt Dev", icon="science", on_click=lambda: prompt_select.set_value("phishing-validation")).props("outline dense").classes("grow")

                with ui.expansion("Output and run log", icon="receipt_long", value=False).classes("w-full"):
                    with ui.column().classes("w-full gap-2 p-2"):
                        output_preview = ui.textarea(label="Output location").props("readonly outlined").classes("w-full sa-code").style("height: 118px;")
                        run_log = ui.textarea(label="Run log").props("readonly outlined").classes("w-full sa-code").style("height: 132px;")

                async def run_validation_check() -> None:
                    if state["running"]:
                        ui.notify("A run is already in progress.", type="warning")
                        return
                    enabled_modules = [name for name, enabled in state["module_enabled"].items() if enabled]
                    if not enabled_modules:
                        ui.notify("Enable at least one detected module.", type="warning")
                        return
                    state["running"] = True
                    run_log.value = "Running validation prompt check\n"
                    validation_result.content = "Running validation prompt check...\n\nThe request has been sent to the selected LLM. Large telemetry mixes can take a few minutes on a local model."
                    validation_run_status.content = "**LLM running** - processing telemetry and prompt."
                    if state["demo_run_button"]:
                        state["demo_run_button"].disable()
                        state["demo_run_button"].props("loading")
                    evidence_path = PROJECT_ROOT / "outputs" / "_prompt_developer_telemetry.json"
                    try:
                        parsed_evidence = json.loads(str(evidence_payload.value or ""))
                    except json.JSONDecodeError as exc:
                        ui.notify(f"Telemetry JSON is invalid: {exc}", type="negative")
                        if state["demo_run_button"]:
                            state["demo_run_button"].enable()
                        state["running"] = False
                        return
                    evidence_path.parent.mkdir(parents=True, exist_ok=True)
                    evidence_path.write_text(json.dumps(parsed_evidence, indent=2), encoding="utf-8")
                    active_profile = load_llm_profile(str(state.get("active_llm_profile") or "local-llamacpp"))
                    estimate = _rough_token_estimate(
                        current_editor_profile().system_prompt,
                        current_editor_profile().user_prompt,
                        str(evidence_payload.value or ""),
                    )
                    usable_context = active_profile.context_size - max(1024, int(active_profile.context_size * 0.15))
                    if estimate > usable_context:
                        validation_result.content = (
                            f"Validation run not started: estimated prompt size `{estimate:,}` tokens exceeds "
                            f"usable context `{usable_context:,}` for `{active_profile.name}`.\n\n"
                            "Reduce background telemetry/noise or increase the LLM profile context size."
                        )
                        validation_run_status.content = "**Blocked** - prompt is larger than configured LLM context."
                        if state["demo_run_button"]:
                            state["demo_run_button"].enable()
                            state["demo_run_button"].props(remove="loading")
                        state["running"] = False
                        return
                    cmd = [
	                        sys.executable,
	                        "-m",
	                        "src.scan_assess",
	                        "--prompt-dev-evidence",
	                        str(evidence_path),
	                    ]
                    if prompt_select.value:
                        cmd.extend(["--prompt-profile", str(prompt_select.value)])
                    if state.get("active_llm_profile"):
                        cmd.extend(["--llm-profile", str(state["active_llm_profile"])])
                    env = os.environ.copy()
                    env["SCAN_ASSESS_ENABLED_MODULES"] = ",".join(enabled_modules)
                    env["SCAN_ASSESS_RUN_PURPOSE"] = "validation"
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        cwd=PROJECT_ROOT,
                        env=env,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    output, _ = await process.communicate()
                    output_text = output.decode("utf-8", errors="replace")
                    run_log.value += output_text
                    run_log.value += f"\nExit code: {process.returncode}"
                    report_line = next((line for line in output_text.splitlines() if line.startswith("Report saved to:")), "")
                    report_path = Path(report_line.removeprefix("Report saved to:").strip()) if report_line else None
                    if report_path and report_path.exists():
                        validation_result.content = report_path.read_text(encoding="utf-8")
                    else:
                        validation_result.content = f"Validation run finished with exit code `{process.returncode}`.\n\n```text\n{output_text[-4000:]}\n```"
                    if state["demo_run_button"]:
                        state["demo_run_button"].enable()
                        state["demo_run_button"].props(remove="loading")
                    state["running"] = False
                    validation_run_status.content = "**Idle** - last validation run finished." if process.returncode == 0 else "**Run failed** - see output below."
                    refresh_runs()
                    refresh_reports()
                    ui.notify("Run complete." if process.returncode == 0 else "Run failed.", type="positive" if process.returncode == 0 else "negative")

                def save_dnscap_runtime_config() -> None:
                    log_root = str(state.get("dnscap_log_root") or "").strip()
                    period = str(state.get("dnscap_period") or "all").strip()
                    start = str(state.get("dnscap_start") or "").strip()
                    end = str(state.get("dnscap_end") or "").strip()
                    values: dict[str, str | None] = {
                        "log_root": log_root or None,
                        "period": period,
                        "start": start if period == "custom" and start else None,
                        "end": end if period == "custom" and end else None,
                        "update_last_run_marker": bool(state.get("dnscap_use_last_run_marker", False)),  # type: ignore[dict-item]
                        "use_last_run_marker": bool(state.get("dnscap_use_last_run_marker", False)),  # compatibility
                        "last_run_utc": str(state.get("dnscap_last_run_utc") or "") or None,
                    }
                    write_module_runtime_config(MODULES_ROOT / "dnscap", values)

                async def run_live_assessment() -> None:
                    if state["running"]:
                        ui.notify("A run is already in progress.", type="warning")
                        return
                    enabled_modules = [name for name, enabled in state["module_enabled"].items() if enabled]
                    if not enabled_modules:
                        ui.notify("Enable at least one detected module.", type="warning")
                        return
                    state["running"] = True
                    run_log.value = "Running assessment\n"
                    assessment_run_button.disable()
                    cmd = [sys.executable, "-u", "-m", "src.scan_assess", "--live"]
                    if prompt_select.value:
                        cmd.extend(["--prompt-profile", str(prompt_select.value)])
                    if state.get("active_llm_profile"):
                        cmd.extend(["--llm-profile", str(state["active_llm_profile"])])
                    env = os.environ.copy()
                    env["SCAN_ASSESS_ENABLED_MODULES"] = ",".join(enabled_modules)
                    if bool(report_token_cap_enabled.value):
                        env["SCAN_ASSESS_MAX_REPORT_TOKENS"] = str(int(report_token_cap.value or 1200))
                    else:
                        env.pop("SCAN_ASSESS_MAX_REPORT_TOKENS", None)
                    save_dnscap_runtime_config()
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        cwd=PROJECT_ROOT,
                        env=env,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    assert process.stdout is not None
                    while True:
                        chunk = await process.stdout.read(4096)
                        if not chunk:
                            break
                        run_log.value += chunk.decode("utf-8", errors="replace")
                        run_log.update()
                    await process.wait()
                    run_log.value += f"\nExit code: {process.returncode}"
                    latest_dnscap = load_module_runtime_config(MODULES_ROOT / "dnscap")
                    state["dnscap_last_run_utc"] = str(latest_dnscap.get("last_run_utc") or "")
                    assessment_run_button.enable()
                    state["running"] = False
                    refresh_visible_llm()
                    refresh_runs()
                    refresh_reports()
                    ui.notify("Assessment complete." if process.returncode == 0 else "Assessment failed.", type="positive" if process.returncode == 0 else "negative")

                def current_llm_profile_from_editor() -> LlmProfile:
                    selected_name = str(llm_select.value or state.get("active_llm_profile") or "local-llamacpp")
                    try:
                        selected_profile = load_llm_profile(selected_name)
                    except FileNotFoundError:
                        selected_profile = load_llm_profile("local-llamacpp")
                    provider = selected_profile.provider
                    return LlmProfile(
                        name=str(llm_name.value or "").strip(),
                        provider=provider,
                        base_url=str(llm_base_url.value or "").strip(),
                        model=str(llm_model.value or "").strip(),
                        api_key="not-needed" if provider == "openai-compatible-local" and not str(llm_api_key_env.value or "").strip() else None,
                        api_key_env=str(llm_api_key_env.value or "").strip() or None,
                        description=str(llm_description.value or "").strip(),
                        context_size=int(llm_context_size.value or 32768),
                        local_model_path=str(llm_local_model_path.value or "").strip() or None,
                        local_server_binary=str(llm_local_server_binary.value or "llama-server").strip(),
                        local_server_host=str(llm_local_server_host.value or "127.0.0.1").strip(),
                        local_server_port=int(llm_local_server_port.value or 8033),
                    )

                def load_llm_into_editor() -> None:
                    try:
                        profile = load_llm_profile(str(llm_select.value or "local-llamacpp"))
                    except FileNotFoundError as exc:
                        llm_status.content = f"LLM profile error: {exc}"
                        return
                    llm_name.value = profile.name
                    llm_model.value = profile.model
                    llm_base_url.value = profile.base_url
                    llm_api_key_env.value = profile.api_key_env or ""
                    llm_description.value = profile.description
                    llm_context_size.value = profile.context_size
                    llm_local_model_path.value = profile.local_model_path or ""
                    llm_local_server_binary.value = profile.local_server_binary
                    llm_local_server_host.value = profile.local_server_host
                    llm_local_server_port.value = profile.local_server_port
                    warnings = validate_llm_profile(profile)
                    warning_text = "\n".join(f"- {item}" for item in warnings) if warnings else "- Ready"
                    llm_status.content = (
                        f"Selected target: `{profile.model}` at `{profile.base_url}`\n\n"
                        f"{warning_text}"
                    )

                def save_llm_editor() -> None:
                    profile = current_llm_profile_from_editor()
                    if not profile.name:
                        ui.notify("LLM profile needs a name.", type="warning")
                        return
                    warnings = validate_llm_profile(profile)
                    save_llm_profile(profile)
                    llm_select.set_options(_display_options(list_llm_profiles()), value=profile.name)
                    load_llm_into_editor()
                    refresh_visible_llm()
                    if warnings:
                        ui.notify("LLM profile saved with warnings.", type="warning")
                    else:
                        ui.notify("LLM profile saved.", type="positive")

                save_llm_button.on("click", lambda event: save_llm_editor())

                def update_mode_controls() -> None:
                    try:
                        output_preview.content = _next_output_preview("assessment")
                    except AttributeError:
                        output_preview.value = _next_output_preview("assessment")
                    load_llm_into_editor()
                    if state["demo_run_button"]:
                        state["demo_run_button"].enable()

                llm_select.on_value_change(lambda event: update_mode_controls())
                update_mode_controls()

                assessment_run_button = ui.button("Run Assessment", icon="security", on_click=run_live_assessment).classes("w-full")

                with ui.expansion("Detected modules", icon="extension", value=False).classes("w-full"):
                    with ui.column().classes("w-full gap-1 p-2 sa-module-list"):
                        for row in _module_rows():
                            with ui.row().classes("w-full items-center justify-between"):
                                with ui.column().classes("gap-0"):
                                    ui.label(row["module"]).classes("font-medium")
                                    ui.label(row["status"]).classes("sa-muted text-xs")
                                if row["status"] == "detected":
                                    ui.switch(
                                        "",
                                        value=state["module_enabled"].get(row["module"], True),
                                        on_change=lambda event, name=row["module"]: state["module_enabled"].__setitem__(name, bool(event.value)),
                                    )
                                else:
                                    ui.badge("no runner", color="secondary")

            with ui.column().classes("sa-workspace"):
                with ui.tabs().classes("w-full sa-nav") as tabs:
                    reports_tab = ui.tab("Reports", icon="article")
                    prompt_developer_tab = ui.tab("Validation", icon="science")
                    evidence_tab = ui.tab("Telemetry", icon="data_object")
                    llm_setup_tab = ui.tab("LLM Setup", icon="settings_applications")
                    modules_tab = ui.tab("Modules", icon="extension")
                    evidence_generator_tab = ui.tab("Telemetry Editor", icon="playlist_add")

                panels = ui.tab_panels(tabs, value=reports_tab).classes("w-full sa-panels")
                with panels:
                    with ui.tab_panel(reports_tab).classes("p-0"):
                        with ui.column().classes("sa-band p-3 gap-2 w-full sa-page sa-reports-page"):
                            with ui.row().classes("w-full items-center justify-between"):
                                ui.label("Reports").classes("text-lg font-semibold")
                                ui.badge("Real scan path", color="primary").classes("text-sm")
                            with ui.column().classes("sa-band p-3 gap-2 w-full sa-scan-card"):
                                ui.label("Scan Settings").classes("font-semibold")
                                with ui.element("div").classes("sa-scan-row w-full"):
                                    prompt_select = ui.select(
                                        _display_options(list_prompt_profiles()),
                                        label="Prompt profile",
                                        value="default",
                                    ).classes("w-full")
                                    selected_llm_summary = ui.markdown("").classes("sa-muted sa-scan-meta")
                                    assessment_context_capacity = ui.markdown("").classes("sa-band p-2 sa-muted sa-code sa-scan-output")
                                    output_preview = ui.markdown("").classes("sa-band p-2 sa-muted sa-code sa-scan-output")
                                    assessment_run_button = ui.button("Run Assessment", icon="security", on_click=run_live_assessment).classes("w-full")
                                with ui.row().classes("w-full gap-3 items-end"):
                                    report_token_cap_enabled = ui.checkbox(
                                        "Limit report output",
                                        value=bool(state["report_token_cap_enabled"]),
                                    ).classes("sa-muted")
                                    report_token_cap = ui.number(
                                        "Max report output tokens",
                                        value=int(state["report_token_cap"]),
                                        min=128,
                                        max=8192,
                                        step=128,
                                    ).classes("sa-small-field")

                                    def sync_report_token_cap() -> None:
                                        state["report_token_cap_enabled"] = bool(report_token_cap_enabled.value)
                                        state["report_token_cap"] = int(report_token_cap.value or 1200)
                                        if report_token_cap_enabled.value:
                                            report_token_cap.enable()
                                        else:
                                            report_token_cap.disable()

                                    report_token_cap_enabled.on_value_change(lambda event: sync_report_token_cap())
                                    report_token_cap.on_value_change(lambda event: sync_report_token_cap())
                                    sync_report_token_cap()
                                ui.markdown(f"**Run machine:** `{_current_machine_label()}`").classes("sa-muted sa-scan-meta")
                                run_log = ui.textarea(label="Run log").props("readonly outlined").classes("w-full sa-code sa-run-log")
                            with ui.row().classes("w-full gap-3 items-end"):
                                report_select = ui.select(_report_options(), label="Report").classes("grow")
                                show_validation_reports = ui.checkbox("Show validation reports", value=False).classes("sa-muted")
                                ui.button("Refresh", icon="refresh", on_click=lambda: refresh_reports())
                            with ui.element("div").classes("w-full sa-report-grid"):
                                report_view = ui.markdown("No reports have been generated in this worktree yet.").classes("sa-band p-3 sa-report-view")
                                with ui.column().classes("sa-band p-3 gap-2 sa-report-context"):
                                    ui.label("Contextual Information").classes("text-base font-semibold")
                                    report_meta = ui.markdown("")
                                    report_context_actions = ui.column().classes("gap-1 w-full")
                                    ui.separator()
                                    ui.label("Telemetry Used By Report").classes("font-semibold")
                                    report_evidence_links = ui.column().classes("gap-1 w-full")
                                    ui.separator()
                                    ui.label("Supporting Run Files").classes("font-semibold")
                                    report_supporting_links = ui.column().classes("gap-1 w-full")

                            def load_report() -> None:
                                report_name = str(report_select.value or "")
                                if not report_name:
                                    report_view.content = (
                                        "No reports have been generated in this worktree yet.\n\n"
                                        f"After a run, reports appear in `{REPORTS_ROOT}` and telemetry appears in `{OUTPUTS_ROOT}/<run>/`."
                                    )
                                    report_meta.content = "### Output Paths\n" + _next_output_preview("assessment")
                                    report_context_actions.clear()
                                    report_evidence_links.clear()
                                    report_supporting_links.clear()
                                    return
                                report_path = REPORTS_ROOT / report_name
                                report_text = report_path.read_text(encoding="utf-8") if report_path.exists() else "Report file not found."
                                run_name = _run_name_from_report(report_name)
                                manifest = _run_manifest(run_name)
                                run_machine = manifest.get("run_machine", {})
                                if not isinstance(run_machine, dict):
                                    run_machine = {}
                                run_machine_label = str(run_machine.get("hostname") or "not recorded")
                                run_platform_label = str(run_machine.get("platform") or "not recorded")
                                generated_local = manifest.get("generated_at_local") or (_european_datetime_label(run_name) if run_name else "not recorded")
                                primary_files, supporting_files = _report_context_files(run_name, report_text)
                                report_view.content = report_text
                                report_meta.content = (
                                    f"**Report:** `reports/{report_name}`\n\n"
                                    f"**Generated:** `{generated_local}`\n\n"
                                    f"**Linked run:** `{_run_display_label(run_name) if run_name else 'unknown'}`\n\n"
                                    f"**Run machine:** `{run_machine_label}`\n\n"
                                    f"**Platform:** `{run_platform_label}`\n\n"
                                    f"**Prompt:** `{manifest.get('prompt_profile', 'unknown')}`\n\n"
                                    f"**LLM:** `{manifest.get('llm_model', 'unknown')}` at `{manifest.get('llm_base_url', 'unknown')}`\n\n"
                                    f"{_manifest_runtime_config_markdown(manifest)}"
                                )
                                report_context_actions.clear()
                                with report_context_actions:
                                    if run_name:
                                        ui.button(
                                            "Open run manifest",
                                            icon="receipt_long",
                                            on_click=lambda r=run_name: open_evidence_from_report(r, "run_manifest.json"),
                                        ).props("flat dense").classes("w-full sa-context-button")
                                        ui.button(
                                            "Open full telemetry browser",
                                            icon="account_tree",
                                            on_click=lambda r=run_name: open_run_from_report(r),
                                        ).props("flat dense").classes("w-full sa-context-button")
                                    else:
                                        ui.markdown("No linked run could be inferred from this report name.")
                                report_evidence_links.clear()
                                with report_evidence_links:
                                    if primary_files:
                                        for file_name in primary_files:
                                            ui.button(
                                                file_name,
                                                icon="travel_explore",
                                                on_click=lambda f=file_name, r=run_name: open_evidence_from_report(r, f),
                                            ).props("flat dense").classes("w-full sa-context-button")
                                    else:
                                        ui.markdown("No input telemetry files were recorded for this report.")
                                report_supporting_links.clear()
                                with report_supporting_links:
                                    if supporting_files:
                                        for file_name in supporting_files[:12]:
                                            ui.button(
                                                file_name,
                                                icon="data_object",
                                                on_click=lambda f=file_name, r=run_name: open_evidence_from_report(r, f),
                                            ).props("flat dense").classes("w-full sa-context-button")
                                        if len(supporting_files) > 12:
                                            ui.markdown(f"`{len(supporting_files) - 12}` more files are available in the Telemetry tab.")
                                    else:
                                        ui.markdown("No additional run files found.")

                            def refresh_reports() -> None:
                                options = _report_options(bool(show_validation_reports.value))
                                selected = next(iter(options.keys()), None)
                                report_select.set_options(options, value=selected)
                                load_report()

                            report_select.on_value_change(lambda event: load_report())
                            show_validation_reports.on_value_change(lambda event: refresh_reports())
                            refresh_reports()

                    with ui.tab_panel(prompt_developer_tab).classes("p-0"):
                        with ui.column().classes("sa-band p-3 gap-2 w-full sa-page sa-prompt-dev-page"):
                            with ui.row().classes("w-full items-center justify-between"):
                                ui.label("Validation").classes("text-lg font-semibold")
                                with ui.row().classes("items-center gap-3"):
                                    validation_run_status = ui.markdown("**Idle** - ready to run a prompt check.").classes("sa-muted text-sm")
                                    state["demo_run_button"] = ui.button("Run Prompt Check", icon="play_arrow", on_click=run_validation_check)
                            with ui.row().classes("w-full gap-3 items-end"):
                                test_suite_select = ui.select(
                                    _display_options(_list_test_suites()),
                                    label="Test suite",
                                    value=state["active_test_suite"],
                                ).style("width: 260px;")
                                test_suite_name = ui.input(
                                    "Suite name",
                                    value=state["active_test_suite"] or "full-validation",
                                ).style("width: 220px;")
                                save_test_suite_button = ui.button("Save Suite", icon="save").props("outline dense")
                                background_run_select = ui.select(
                                    {"": "Generated baseline only", **_run_options()},
                                    label="Background telemetry",
                                    value="",
                                ).style("width: 320px;")
                                with ui.column().classes("gap-0").style("width: 260px;"):
                                    background_noise_label = ui.label(f"Background noise: {state['background_noise']}").classes("sa-muted text-xs")
                                    background_noise_slider = ui.slider(min=0, max=80, step=5, value=state["background_noise"]).props("label")
                                profile_name = ui.input("Profile name").style("width: 220px;")
                                lock_status = ui.badge("", color="secondary").classes("text-sm")
                            with ui.row().classes("w-full gap-3"):
                                system_prompt = ui.textarea("System prompt").classes("sa-code sa-prompt-box")
                                user_prompt = ui.textarea("User prompt").classes("sa-code sa-prompt-box")
                            with ui.element("div").classes("w-full sa-prompt-dev-main"):
                                with ui.column().classes("gap-2 sa-prompt-actions"):
                                    with ui.row().classes("gap-2"):
                                        ui.button("Validate", icon="fact_check", on_click=lambda: show_prompt_validation()).props("dense")
                                        save_profile_button = ui.button("Save Profile", icon="save", on_click=lambda: save_profile()).props("dense")
                                    validation_output = ui.markdown("").classes("sa-band p-2 sa-compact-scroll")
                                    validation_capacity = ui.markdown("").classes("sa-band p-2 sa-compact-scroll")
                                    positive_summary = ui.markdown("").classes("sa-band p-2 sa-positive-summary")
                                with ui.column().classes("sa-band p-3 sa-validation-output-card"):
                                    ui.label("LLM output").classes("font-semibold")
                                    validation_result = ui.markdown(_latest_report_text(validation_only=True)).classes("sa-validation-output")
                                module_test_column = ui.column().classes("sa-band p-2 gap-2 sa-evidence-generator sa-injector-panel")
                            evidence_payload = ui.textarea("Telemetry sent to the LLM").classes("hidden")

                            def load_profile_into_editor(name: str | None = None) -> None:
                                profile = load_prompt_profile(name or prompt_select.value or "default")
                                state["current_profile"] = profile
                                profile_name.value = profile.name
                                system_prompt.value = profile.system_prompt
                                user_prompt.value = profile.user_prompt
                                locked = profile.name in LOCKED_PROMPT_PROFILES
                                lock_status.text = "Locked NGO default" if locked else "Editable profile"
                                profile_name.disable() if locked else profile_name.enable()
                                for element in [system_prompt, user_prompt]:
                                    element.enable()
                                    if locked:
                                        element.props("readonly")
                                    else:
                                        element.props(remove="readonly")
                                save_profile_button.disable() if locked else save_profile_button.enable()
                                show_prompt_validation()

                            def current_editor_profile() -> PromptProfile:
                                tags = state["current_profile"].tags
                                return PromptProfile(
                                    name=str(profile_name.value or "").strip(),
                                    description=state["current_profile"].description,
                                    tags=tags,
                                    system_prompt=str(system_prompt.value or ""),
                                    user_prompt=str(user_prompt.value or ""),
                                )

                            def show_prompt_validation() -> None:
                                warnings = validate_prompt_profile(current_editor_profile())
                                validation_output.content = "Prompt validation passed." if not warnings else "\n".join(f"- {item}" for item in warnings)

                            def save_profile() -> None:
                                profile = current_editor_profile()
                                if not profile.name:
                                    ui.notify("Prompt profile needs a name.", type="warning")
                                    return
                                if profile.name in LOCKED_PROMPT_PROFILES:
                                    ui.notify("The default prompt is locked. Switch to another profile or create a new YAML profile.", type="warning")
                                    return
                                save_prompt_profile(profile)
                                prompt_select.set_options(_display_options(list_prompt_profiles()), value=profile.name)
                                show_prompt_validation()
                                ui.notify("Prompt profile saved.", type="positive")

                            prompt_select.on_value_change(lambda event: load_profile_into_editor(event.value))

                            def refresh_prompt_developer_evidence() -> None:
                                evidence_payload.value = _prompt_developer_evidence(
                                    state["module_tests"],
                                    str(background_run_select.value or "") or None,
                                    state["module_scopes"],
                                    int(state["background_noise"]),
                                )
                                positives = _selected_positive_summary(state["module_tests"])
                                background_text = str(background_run_select.value or "")
                                positive_summary.content = (
                                    "**Telemetry mix**\n\n"
                                    f"- Background: `{background_text or 'generated baseline only'}`\n"
                                    f"- Generated background telemetry files: `{state['background_noise']}`\n"
                                    f"- Injected positives: {', '.join(positives) if positives else '`none`'}"
                                )
                                if state.get("generator_summary") is not None:
                                    state["generator_summary"].content = positive_summary.content
                                try:
                                    validation_capacity.content = _llm_capacity_markdown(
                                        load_llm_profile(str(state.get("active_llm_profile") or "local-llamacpp")),
                                        str(evidence_payload.value or ""),
                                        current_editor_profile(),
                                    )
                                except Exception as exc:
                                    validation_capacity.content = f"Context estimate unavailable: `{exc}`"

                            def update_module_test(module_name: str, value: str) -> None:
                                state["module_tests"][module_name] = value
                                refresh_prompt_developer_evidence()

                            def update_module_scope(module_name: str, value: str) -> None:
                                state["module_scopes"][module_name] = value
                                refresh_prompt_developer_evidence()

                            def update_background_run(value: str | None) -> None:
                                state["background_run"] = value or ""
                                refresh_prompt_developer_evidence()

                            def update_background_noise(value: int | float | None) -> None:
                                state["background_noise"] = int(value or 0)
                                background_noise_label.text = f"Background noise: {state['background_noise']}"
                                refresh_prompt_developer_evidence()

                            def render_evidence_injector() -> None:
                                refresh_prompt_developer_evidence()
                                module_test_column.clear()
                                with module_test_column:
                                    ui.label("Telemetry Injector").classes("font-semibold")
                                    ui.label("Select which module-owned validation telemetry is injected into this validation run. Use Telemetry Editor for file-level editing.").classes("sa-muted text-xs")
                                    for row in _module_rows():
                                        if row["status"] != "detected":
                                            continue
                                        module_options = _module_test_options(row["module"])
                                        default_choice = _normalise_validation_choice(state["module_tests"].get(row["module"], "nominal"))
                                        if default_choice not in module_options:
                                            default_choice = "nominal" if "nominal" in module_options else next(iter(module_options))
                                        ui.markdown(f"**{row['module']}**").classes("sa-muted")
                                        warning = _module_validation_warning(row["module"])
                                        if warning:
                                            ui.label(warning).classes("sa-muted text-xs")
                                        ui.select(
                                            module_options,
                                            label="Telemetry to inject",
                                            value=default_choice,
                                            on_change=lambda event, name=row["module"]: update_module_test(name, str(event.value)),
                                        ).props("dense outlined").classes("w-full")
                            background_run_select.on_value_change(lambda event: update_background_run(str(event.value or "")))
                            background_noise_slider.on_value_change(lambda event: update_background_noise(event.value))
                            load_profile_into_editor(prompt_select.value)
                            render_evidence_injector()

                            def current_test_suite_data() -> dict[str, Any]:
                                return {
                                    "name": str(test_suite_name.value or test_suite_select.value or "validation-suite"),
                                    "description": "Saved validation test suite from the GUI.",
                                    "background_noise": int(state["background_noise"]),
                                    "module_tests": state["module_tests"],
                                    "module_scopes": state["module_scopes"],
                                }

                            def load_test_suite_into_validation(name: str | None) -> None:
                                if not name:
                                    return
                                suite = _load_test_suite(str(name))
                                state["active_test_suite"] = str(name)
                                test_suite_name.value = str(name)
                                state["module_tests"] = {
                                    row["module"]: _normalise_validation_choice((suite.get("module_tests") or {}).get(row["module"], state["module_tests"].get(row["module"], "nominal")))
                                    for row in _module_rows()
                                    if row["status"] == "detected"
                                }
                                state["module_scopes"] = {
                                    row["module"]: (suite.get("module_scopes") or {}).get(row["module"], _module_scope_value(row["module"], state["module_scopes"]))
                                    for row in _module_rows()
                                    if row["status"] == "detected"
                                }
                                update_background_noise(int(suite.get("background_noise", state["background_noise"])))
                                background_noise_slider.value = state["background_noise"]
                                render_evidence_injector()
                                ui.notify(f"Loaded test suite: {name}", type="positive")

                            def save_current_test_suite() -> None:
                                name = str(test_suite_name.value or test_suite_select.value or state["active_test_suite"] or "full-validation").strip()
                                path = _save_test_suite(name, current_test_suite_data())
                                test_suite_select.set_options(_display_options(_list_test_suites()), value=path.stem)
                                state["active_test_suite"] = path.stem
                                ui.notify(f"Saved test suite: {path.stem}", type="positive")

                            test_suite_select.on_value_change(lambda event: load_test_suite_into_validation(str(event.value or "")))
                            save_test_suite_button.on("click", lambda event: save_current_test_suite())
                            if state["active_test_suite"]:
                                load_test_suite_into_validation(state["active_test_suite"])

                    with ui.tab_panel(evidence_generator_tab).classes("p-0"):
                        with ui.column().classes("sa-band p-3 w-full sa-page sa-generator-page"):
                            with ui.row().classes("w-full items-center justify-between"):
                                with ui.column().classes("gap-0"):
                                    ui.label("Telemetry Editor").classes("text-lg font-semibold")
                                    ui.label("Edit module-owned validation telemetry files. These JSON files live inside each module folder.").classes("sa-muted text-sm")
                                ui.button("Open Validation", icon="science", on_click=lambda: tabs.set_value(prompt_developer_tab)).props("outline dense")
                            with ui.element("div").classes("sa-generator-layout w-full"):
                                generator_modules = ui.column().classes("sa-generator-modules gap-2")
                                with ui.column().classes("gap-2 sa-generator-right"):
                                    state["generator_summary"] = ui.markdown("").classes("sa-band p-3")
                                    with ui.row().classes("w-full gap-2"):
                                        ui.button("Validate JSON", icon="fact_check", on_click=lambda: validate_generator_payload()).props("outline dense").classes("grow")
                                        ui.button("Apply to Validation", icon="published_with_changes", on_click=lambda: apply_generator_payload()).props("outline dense").classes("grow")
                                        ui.button("Save Module Telemetry", icon="save", on_click=lambda: save_generator_payload()).props("dense").classes("grow")
                                    generator_save_status = ui.markdown("").classes("sa-muted text-sm sa-generator-status")
                                    state["generator_preview"] = ui.textarea("Module telemetry JSON").props("outlined spellcheck=false").classes("sa-code sa-generator-preview")

                            def _current_generator_json() -> dict[str, Any] | list[Any]:
                                raw_text = str(state["generator_preview"].value or "")
                                parsed = json.loads(raw_text)
                                if not isinstance(parsed, (dict, list)):
                                    raise ValueError("Telemetry payload must be a JSON object or array.")
                                return parsed

                            def _current_generator_selection() -> tuple[str, str, str]:
                                detected = [row["module"] for row in _module_rows() if row["status"] == "detected"]
                                module_name = str(state.get("generator_selected_module") or (detected[0] if detected else ""))
                                if not module_name:
                                    return "", "nominal", "module_default"
                                selected = _normalise_validation_choice(state["module_tests"].get(module_name, "nominal"))
                                options = _module_test_options(module_name)
                                if selected not in options:
                                    selected = "nominal" if "nominal" in options else next(iter(options))
                                scope = _module_scope_value(module_name, state["module_scopes"])
                                return module_name, selected, scope

                            def load_generator_payload(module_name: str | None = None) -> None:
                                if module_name:
                                    state["generator_selected_module"] = module_name
                                selected_module, selected_condition, selected_scope = _current_generator_selection()
                                if not selected_module:
                                    state["generator_preview"].value = ""
                                    generator_save_status.content = "No module selected."
                                    return
                                document = _module_validation_telemetry_document(selected_module, selected_condition, selected_scope, generate_missing=True)
                                state["generator_preview"].value = json.dumps(document, indent=2, sort_keys=False)
                                generator_save_status.content = (
                                    f"Editing `{_module_validation_telemetry_display_path(selected_module, selected_condition, selected_scope)}`"
                                )

                            def validate_generator_payload() -> None:
                                try:
                                    parsed = _current_generator_json()
                                except (json.JSONDecodeError, ValueError) as exc:
                                    generator_save_status.content = f"JSON validation failed: `{exc}`"
                                    ui.notify(f"Telemetry JSON is invalid: {exc}", type="negative")
                                    return
                                pretty = json.dumps(parsed, indent=2, sort_keys=False)
                                state["generator_preview"].value = pretty
                                generator_save_status.content = "JSON validation passed. Payload was formatted."
                                ui.notify("Telemetry JSON is valid.", type="positive")

                            def apply_generator_payload() -> None:
                                save_generator_payload()
                                refresh_prompt_developer_evidence()
                                ui.notify("Module telemetry is now used by Validation.", type="positive")

                            def save_generator_payload() -> None:
                                try:
                                    parsed = _current_generator_json()
                                except (json.JSONDecodeError, ValueError) as exc:
                                    generator_save_status.content = f"Cannot save invalid JSON: `{exc}`"
                                    ui.notify(f"Telemetry JSON is invalid: {exc}", type="negative")
                                    return
                                selected_module, selected_condition, selected_scope = _current_generator_selection()
                                if not selected_module:
                                    ui.notify("Select a module telemetry file first.", type="warning")
                                    return
                                target = _write_module_validation_telemetry(selected_module, selected_condition, selected_scope, parsed)
                                document = _module_validation_telemetry_document(selected_module, selected_condition, selected_scope, generate_missing=False)
                                state["generator_preview"].value = json.dumps(document, indent=2, sort_keys=False)
                                refresh_prompt_developer_evidence()
                                generator_save_status.content = f"Saved `{target.relative_to(PROJECT_ROOT)}` and applied to Validation."
                                ui.notify("Module telemetry saved.", type="positive")

                            def refresh_generator_page() -> None:
                                generator_modules.clear()
                                with generator_modules:
                                    for row in _module_rows():
                                        if row["status"] != "detected":
                                            continue
                                        module_name = row["module"]
                                        module_options = _module_test_options(module_name)
                                        selected = _normalise_validation_choice(state["module_tests"].get(module_name, "nominal"))
                                        if selected not in module_options:
                                            selected = "nominal" if "nominal" in module_options else next(iter(module_options))
                                        scope_options = _module_scope_options(module_name)
                                        selected_scope = _module_scope_value(module_name, state["module_scopes"])
                                        with ui.column().classes("sa-band p-3 gap-2 sa-generator-card"):
                                            with ui.row().classes("w-full items-center justify-between"):
                                                ui.label(module_name).classes("font-semibold text-lg")
                                                ui.badge("module telemetry", color="primary")
                                            ui.label("Select the telemetry condition this module should contribute to the validation payload.").classes("sa-muted text-xs")
                                            warning = _module_validation_warning(module_name)
                                            if warning:
                                                ui.label(warning).classes("sa-muted text-xs")
                                            ui.select(
                                                module_options,
                                                label="Telemetry condition",
                                                value=selected,
                                                on_change=lambda event, name=module_name: update_generator_module_choice(name, str(event.value)),
                                            ).props("dense outlined").classes("w-full")
                                            if len(scope_options) > 1:
                                                ui.select(
                                                    scope_options,
                                                    label="Asset perspective",
                                                    value=selected_scope,
                                                    on_change=lambda event, name=module_name: update_generator_module_scope(name, str(event.value)),
                                                ).props("dense outlined").classes("w-full")
                                            else:
                                                ui.markdown(f"**Asset perspective:** `{next(iter(scope_options.values()))}`").classes("sa-muted text-xs")
                                            ui.markdown(
                                                f"Editing file `{_module_validation_telemetry_display_path(module_name, selected, selected_scope)}`."
                                            ).classes("sa-muted text-xs")
                                            ui.button(
                                                "Edit this module telemetry",
                                                icon="edit",
                                                on_click=lambda name=module_name: load_generator_payload(name),
                                            ).props("outline dense").classes("w-full")
                                refresh_prompt_developer_evidence()
                                load_generator_payload()

                            def update_generator_module_choice(module_name: str, value: str) -> None:
                                update_module_test(module_name, value)
                                state["generator_selected_module"] = module_name
                                refresh_generator_page()

                            def update_generator_module_scope(module_name: str, value: str) -> None:
                                update_module_scope(module_name, value)
                                state["generator_selected_module"] = module_name
                                refresh_generator_page()
                            refresh_generator_page()

                    with ui.tab_panel(evidence_tab).classes("p-0"):
                        with ui.column().classes("sa-band p-3 gap-2 w-full sa-page sa-evidence-page"):
                            ui.label("Telemetry Browser").classes("text-lg font-semibold")
                            with ui.row().classes("w-full gap-3 items-end"):
                                run_select = ui.select(_run_options(), label="Run").classes("grow")
                                ui.button("Refresh", icon="refresh", on_click=lambda: refresh_runs())
                            with ui.element("div").classes("w-full sa-evidence-layout"):
                                with ui.column().classes("sa-evidence-left"):
                                    ui.label("Module Output Folders").classes("font-semibold")
                                    evidence_tree = ui.tree([], label_key="label", on_select=lambda event: open_evidence_from_tree(event.value)).classes("sa-band p-2 w-full sa-evidence-tree")
                                    evidence_summary = ui.markdown("").classes("sa-band p-3 w-full")
                                with ui.column().classes("sa-evidence-right"):
                                    ui.label("Selected Telemetry").classes("font-semibold")
                                    highlight_markdown = ui.markdown("Select a telemetry file to inspect it.").classes("sa-band p-3 sa-evidence-highlight")
                                    json_container = ui.column().classes("sa-band p-2 w-full sa-evidence-json")

                            def load_run() -> None:
                                run_name = str(run_select.value or "")
                                nodes = _tree_nodes_for_run(run_name)
                                evidence_tree.props["nodes"] = nodes
                                evidence_tree.props["expanded"] = _tree_expanded_keys(nodes)
                                evidence_tree.props["selected"] = None
                                evidence_tree.update()
                                evidence_summary.content = _evidence_empty_message(run_name)
                                json_container.clear()
                                highlight_markdown.content = "Select a telemetry file to see relevant fields."

                            def open_evidence(file_name: str) -> None:
                                run_name = str(run_select.value or "")
                                if not run_name or not file_name:
                                    return
                                path = OUTPUTS_ROOT / run_name / file_name
                                display_type, data = _read_evidence_for_display(path)
                                highlight_markdown.content = _highlight_markdown(file_name, data) if display_type == "json" else f"**Selected:** `{file_name}`\n\nText telemetry file selected."
                                json_container.clear()
                                with json_container:
                                    if display_type == "json":
                                        ui.json_editor(
                                            {
                                                "content": {"json": data},
                                                "mode": "tree",
                                                "readOnly": True,
                                                "mainMenuBar": False,
                                                "navigationBar": True,
                                            }
                                        ).classes("w-full").style("height: 100%;")
                                    else:
                                        ui.textarea(value=str(data)).props("readonly outlined").classes("w-full sa-code sa-evidence-text")

                            def open_evidence_from_tree(value: str | None) -> None:
                                if value and not value.startswith("dir:") and value != "root":
                                    open_evidence(value)

                            def open_evidence_from_report(run_name: str, file_name: str) -> None:
                                run_select.set_options(_run_options(), value=run_name)
                                tabs.set_value(evidence_tab)
                                load_run()
                                open_evidence(file_name)

                            def open_run_from_report(run_name: str) -> None:
                                run_select.set_options(_run_options(), value=run_name)
                                tabs.set_value(evidence_tab)
                                load_run()

                            def refresh_runs() -> None:
                                options = _run_options()
                                selected = next(iter(options.keys()), None)
                                run_select.set_options(options, value=selected)
                                load_run()

                            run_select.on_value_change(lambda event: load_run())
                            refresh_runs()

                    with ui.tab_panel(llm_setup_tab).classes("p-0"):
                        with ui.column().classes("sa-band p-3 gap-2 w-full sa-page"):
                            ui.label("LLM Setup").classes("text-lg font-semibold")
                            ui.label("Select and edit the model endpoint used by Reports and Validation runs.").classes("sa-muted")
                            with ui.element("div").classes("sa-setup-grid w-full"):
                                with ui.column().classes("sa-band p-3 gap-3"):
                                    llm_select = ui.select(
                                        _display_options(list_llm_profiles()),
                                        label="LLM profile",
                                        value=state.get("active_llm_profile"),
                                    ).classes("w-full")
                                    active_llm_status = ui.markdown("").classes("sa-band p-3")
                                    llm_status = ui.markdown("").classes("sa-band p-3")
                                    with ui.row().classes("w-full gap-2"):
                                        load_llm_button = ui.button("Load", icon="download").props("outline dense").classes("grow")
                                        activate_llm_button = ui.button("Activate", icon="radio_button_unchecked").props("outline dense").classes("grow")
                                    with ui.row().classes("w-full gap-2"):
                                        save_llm_button = ui.button("Save Edits", icon="save").props("outline dense").classes("grow")
                                        save_llm_as_button = ui.button("Save As New", icon="add").props("outline dense").classes("grow")
                                    delete_llm_button = ui.button("Delete Selected Profile", icon="delete").props("outline dense color=negative").classes("w-full")
                                with ui.column().classes("sa-band p-3 gap-2"):
                                    with ui.row().classes("w-full gap-3"):
                                        llm_name = ui.input("Profile name").classes("grow sa-small-field")
                                        llm_model = ui.input("Model").classes("grow sa-small-field")
                                    llm_base_url = ui.input("Base URL").classes("w-full sa-small-field")
                                    with ui.row().classes("w-full gap-3"):
                                        llm_api_key_env = ui.input("API key env var").classes("grow sa-small-field")
                                        llm_description = ui.input("Description").classes("grow sa-small-field")
                                    with ui.row().classes("w-full gap-3"):
                                        llm_context_size = ui.number("Context size", value=32768, min=1024, step=1024).classes("grow sa-small-field")
                                        llm_local_server_binary = ui.input("Server binary").classes("grow sa-small-field")
                                    llm_local_model_path = ui.input("Local model path").classes("w-full sa-small-field")
                                    with ui.row().classes("w-full gap-3"):
                                        llm_local_server_host = ui.input("Local host").classes("grow sa-small-field")
                                        llm_local_server_port = ui.number("Local port", value=8033, min=1, max=65535, step=1).classes("grow sa-small-field")
                                    with ui.row().classes("w-full gap-2"):
                                        start_llm_button = ui.button("Start Local Model", icon="play_arrow").props("outline dense").classes("grow")
                                        stop_llm_button = ui.button("Stop Started Model", icon="stop").props("outline dense color=negative").classes("grow")
                                    llm_server_status = ui.markdown("").classes("sa-band p-3")

                            def refresh_visible_llm() -> None:
                                active_name = str(state.get("active_llm_profile") or "")
                                selected_name = str(llm_select.value or "")
                                active_llm_status.content = f"**Active for runs:** `{active_name or 'none'}`"
                                if selected_name and selected_name == active_name:
                                    activate_llm_button.text = "Active"
                                    activate_llm_button.props("outline dense icon=check_circle")
                                    activate_llm_button.disable()
                                else:
                                    activate_llm_button.text = "Activate"
                                    activate_llm_button.props("outline dense icon=radio_button_unchecked")
                                    activate_llm_button.enable()
                                try:
                                    profile = load_llm_profile(active_name or None)
                                    selected_llm_summary.content = (
                                        f"**LLM:** `{profile.name}`\n\n"
                                        f"`{profile.model}` at `{profile.base_url}`\n\n"
                                        f"Context: `{profile.context_size:,}`"
                                    )
                                except FileNotFoundError:
                                    selected_llm_summary.content = "**LLM:** profile not found"
                                try:
                                    assessment_context_capacity.content = _assessment_context_capacity_markdown(
                                        str(prompt_select.value or "default"),
                                        active_name or None,
                                        state["module_enabled"],
                                    )
                                except Exception as exc:
                                    assessment_context_capacity.content = f"**Context estimate:** unavailable\n\n`{exc}`"
                                try:
                                    selected_profile = load_llm_profile(selected_name or active_name or None)
                                    llm_server_status.content = (
                                        f"**Endpoint health:** {_local_llm_health(selected_profile)}\n\n"
                                        f"**Configured context:** `{selected_profile.context_size:,}` tokens"
                                    )
                                except Exception as exc:
                                    llm_server_status.content = f"**Endpoint health:** unavailable: `{exc}`"

                            def activate_llm_editor_profile() -> None:
                                profile_name = str(llm_select.value or "").strip()
                                if not profile_name:
                                    ui.notify("Select a profile to activate.", type="warning")
                                    return
                                state["active_llm_profile"] = profile_name
                                refresh_visible_llm()
                                ui.notify(f"Activated LLM profile: {profile_name}", type="positive")

                            def save_llm_as_new_profile() -> None:
                                profile = current_llm_profile_from_editor()
                                if not profile.name:
                                    ui.notify("Enter a profile name first.", type="warning")
                                    return
                                if profile.name in list_llm_profiles():
                                    ui.notify("That profile already exists. Use Save Edits or choose a new name.", type="warning")
                                    return
                                warnings = validate_llm_profile(profile)
                                save_llm_profile(profile)
                                llm_select.set_options(_display_options(list_llm_profiles()), value=profile.name)
                                state["active_llm_profile"] = profile.name
                                load_llm_into_editor()
                                refresh_visible_llm()
                                ui.notify("New LLM profile saved and activated." if not warnings else "New LLM profile saved with warnings.", type="positive" if not warnings else "warning")

                            def delete_selected_llm_profile() -> None:
                                profile_name = str(llm_select.value or "").strip()
                                if not profile_name:
                                    ui.notify("Select a profile to delete.", type="warning")
                                    return
                                if not delete_llm_profile(profile_name):
                                    ui.notify("Default or missing profiles cannot be deleted.", type="warning")
                                    return
                                remaining = list_llm_profiles()
                                next_profile = "local-llamacpp" if "local-llamacpp" in remaining else next(iter(remaining), None)
                                state["active_llm_profile"] = next_profile
                                llm_select.set_options(_display_options(remaining), value=next_profile)
                                load_llm_into_editor()
                                refresh_visible_llm()
                                ui.notify(f"Deleted LLM profile: {profile_name}", type="positive")

                            async def start_selected_llm_server() -> None:
                                profile = current_llm_profile_from_editor()
                                if profile.provider != "openai-compatible-local":
                                    ui.notify("Only local llama.cpp profiles can be started here.", type="warning")
                                    return
                                if not profile.local_model_path:
                                    ui.notify("Set a local model path first.", type="warning")
                                    return
                                existing = state["settings_processes"].get("llm_server")
                                if existing and existing.returncode is None:
                                    ui.notify("A GUI-started LLM server is already running.", type="warning")
                                    return
                                cmd = [
                                    profile.local_server_binary,
                                    "-m",
                                    profile.local_model_path,
                                    "--ctx-size",
                                    str(profile.context_size),
                                    "--host",
                                    profile.local_server_host,
                                    "--port",
                                    str(profile.local_server_port),
                                ]
                                start_llm_button.disable()
                                llm_server_status.content = f"Starting local model...\n\n`{' '.join(cmd)}`"
                                try:
                                    process = await asyncio.create_subprocess_exec(
                                        *cmd,
                                        cwd=PROJECT_ROOT,
                                        stdout=asyncio.subprocess.PIPE,
                                        stderr=asyncio.subprocess.STDOUT,
                                    )
                                except FileNotFoundError:
                                    start_llm_button.enable()
                                    llm_server_status.content = f"Could not find server binary `{profile.local_server_binary}`."
                                    ui.notify("LLM server binary not found.", type="negative")
                                    return
                                state["settings_processes"]["llm_server"] = process
                                await asyncio.sleep(2)
                                start_llm_button.enable()
                                refresh_visible_llm()
                                ui.notify("Local LLM server start requested.", type="positive")

                            def stop_selected_llm_server() -> None:
                                process = state["settings_processes"].get("llm_server")
                                if not process or process.returncode is not None:
                                    ui.notify("No GUI-started LLM server is active.", type="warning")
                                    return
                                process.terminate()
                                llm_server_status.content = "Stopping GUI-started local LLM server."
                                ui.notify("Stopping local LLM server.", type="positive")

                            llm_select.on_value_change(lambda event: refresh_visible_llm())
                            prompt_select.on_value_change(lambda event: refresh_visible_llm())
                            load_llm_button.on("click", lambda event: load_llm_into_editor())
                            activate_llm_button.on("click", lambda event: activate_llm_editor_profile())
                            save_llm_button.on("click", lambda event: save_llm_editor())
                            save_llm_as_button.on("click", lambda event: save_llm_as_new_profile())
                            delete_llm_button.on("click", lambda event: delete_selected_llm_profile())
                            start_llm_button.on("click", lambda event: start_selected_llm_server())
                            stop_llm_button.on("click", lambda event: stop_selected_llm_server())
                            try:
                                output_preview.content = _next_output_preview("assessment")
                            except AttributeError:
                                output_preview.value = _next_output_preview("assessment")
                            load_llm_into_editor()
                            refresh_visible_llm()

                    with ui.tab_panel(modules_tab).classes("p-0"):
                        with ui.column().classes("sa-band p-3 gap-3 w-full sa-page"):
                            with ui.row().classes("w-full items-center justify-between"):
                                ui.label("Modules").classes("text-lg font-semibold")
                                ui.badge("Detected runners", color="primary")
                            ui.label("Choose which detected modules are included in Reports and Validation runs.").classes("sa-muted")

                            def settings_status_text(surface: dict[str, str]) -> str:
                                host = surface.get("host", "127.0.0.1")
                                port_text = surface.get("port", "0")
                                port = int(port_text) if port_text.isdigit() else 0
                                if port and _local_tcp_port_open(host, port):
                                    return f"Controls page is running at `{surface.get('url')}`."
                                return "Controls page is stopped."

                            async def start_settings_surface(surface: dict[str, str], status: Any) -> bool:
                                host = surface.get("host", "127.0.0.1")
                                port_text = surface.get("port", "0")
                                port = int(port_text) if port_text.isdigit() else 0
                                if port and _local_tcp_port_open(host, port):
                                    status.content = settings_status_text(surface)
                                    ui.notify("Controls page is already running.", type="positive")
                                    return True
                                argv = surface.get("argv", "").split()
                                cwd = PROJECT_ROOT / surface.get("cwd", ".")
                                if not argv or not cwd.exists():
                                    ui.notify("No runnable settings command was detected.", type="negative")
                                    return False
                                key = surface.get("url") or surface.get("label", "settings")
                                process = await asyncio.create_subprocess_exec(
                                    *argv,
                                    cwd=cwd,
                                    stdout=asyncio.subprocess.DEVNULL,
                                    stderr=asyncio.subprocess.DEVNULL,
                                )
                                state["settings_processes"][key] = process
                                for _ in range(20):
                                    await asyncio.sleep(0.25)
                                    if port and _local_tcp_port_open(host, port):
                                        status.content = settings_status_text(surface)
                                        ui.notify("Controls page started.", type="positive")
                                        return True
                                    if process.returncode is not None:
                                        break
                                status.content = "Controls page did not become reachable. Check the command manually."
                                ui.notify("Controls page did not start cleanly.", type="warning")
                                return False

                            async def stop_settings_surface(surface: dict[str, str], status: Any) -> None:
                                key = surface.get("url") or surface.get("label", "settings")
                                process = state["settings_processes"].get(key)
                                if process is None or process.returncode is not None:
                                    status.content = settings_status_text(surface)
                                    ui.notify("No GUI-started controls process is active.", type="warning")
                                    return
                                process.terminate()
                                try:
                                    await asyncio.wait_for(process.wait(), timeout=3)
                                except TimeoutError:
                                    process.kill()
                                    await process.wait()
                                status.content = settings_status_text(surface)
                                ui.notify("Controls page stopped.", type="positive")

                            async def open_settings_surface(surface: dict[str, str], status: Any, dialog: Any) -> None:
                                started = await start_settings_surface(surface, status)
                                host = surface.get("host", "127.0.0.1")
                                port_text = surface.get("port", "0")
                                port = int(port_text) if port_text.isdigit() else 0
                                if started or (port and _local_tcp_port_open(host, port)):
                                    dialog.open()

                            with ui.element("div").classes("sa-module-grid w-full"):
                                for row in _module_rows():
                                    with ui.column().classes("sa-band p-3 gap-2"):
                                        with ui.row().classes("w-full items-center justify-between"):
                                            with ui.column().classes("gap-0"):
                                                ui.label(row["module"]).classes("font-semibold")
                                                ui.label(row["status"]).classes("sa-muted text-xs")
                                            if row["status"] == "detected":
                                                ui.switch(
                                                    "",
                                                    value=state["module_enabled"].get(row["module"], True),
                                                    on_change=lambda event, name=row["module"]: (
                                                        state["module_enabled"].__setitem__(name, bool(event.value)),
                                                        refresh_visible_llm(),
                                                    ),
                                                )
                                            else:
                                                ui.badge("no runner", color="secondary")
                                        if row["runner"]:
                                            ui.markdown(f"`{row['runner']}`").classes("sa-muted")
                                        with ui.expansion("Description", icon="info", value=False).classes("w-full"):
                                            ui.markdown(_module_description_markdown(row["module"])).classes("sa-muted text-sm")
                                        surfaces = [
                                            surface for surface in _module_settings_surfaces(row["module"])
                                            if surface.get("kind") == "web" and row["module"] != "dnscap"
                                        ]
                                        if surfaces:
                                            with ui.expansion("Module controls", icon="settings", value=row["module"] == "quiz").classes("w-full"):
                                                for surface in surfaces:
                                                    with ui.column().classes("sa-band p-2 gap-1 w-full"):
                                                        ui.markdown(f"**{surface['label']}**").classes("sa-muted")
                                                        ui.markdown(surface["detail"]).classes("sa-muted text-sm")
                                                        if surface.get("command"):
                                                            ui.markdown(f"`{surface['command']}`").classes("sa-muted")
                                                        if surface.get("url"):
                                                            status = ui.markdown(settings_status_text(surface)).classes("sa-muted text-sm")
                                                            with ui.dialog().props("persistent") as controls_dialog:
                                                                with ui.card().classes("sa-controls-dialog-card"):
                                                                    with ui.row().classes("w-full items-center justify-between gap-2"):
                                                                        with ui.column().classes("gap-0"):
                                                                            ui.label(surface["label"]).classes("font-semibold")
                                                                            ui.label(surface["url"]).classes("sa-muted text-xs")
                                                                        with ui.row().classes("gap-2"):
                                                                            ui.link("Open in browser tab", surface["url"], new_tab=True).classes("sa-context-button")
                                                                            ui.button("Close", icon="close", on_click=controls_dialog.close).props("outline dense")
                                                                    html.iframe(src=surface["url"], title="Module controls").classes("sa-controls-frame")
                                                            with ui.row().classes("w-full gap-2"):
                                                                ui.button(
                                                                    "Start controls",
                                                                    icon="play_arrow",
                                                                    on_click=lambda s=surface, st=status: start_settings_surface(s, st),
                                                                ).props("outline dense").classes("grow")
                                                                ui.button(
                                                                    "Open here",
                                                                    icon="open_in_full",
                                                                    on_click=lambda s=surface, st=status, dlg=controls_dialog: open_settings_surface(s, st, dlg),
                                                                ).props("outline dense").classes("grow")
                                                                ui.link("Open controls", surface["url"], new_tab=True).classes("sa-context-button grow")
                                                                ui.button(
                                                                    "Stop",
                                                                    icon="stop",
                                                                    on_click=lambda s=surface, st=status: stop_settings_surface(s, st),
                                                                ).props("outline dense color=negative").classes("grow")
                                        with ui.expansion("Validation telemetry options", icon="playlist_add", value=False).classes("w-full"):
                                            capability = _module_validation_capability(row["module"])
                                            manifest_path = str(capability.get("manifest_path") or "")
                                            if manifest_path:
                                                ui.markdown(f"Manifest: `{manifest_path}`").classes("sa-muted text-sm")
                                            else:
                                                ui.markdown("Options are exposed by `runner.py`; no telemetry manifest JSON was found.").classes("sa-muted text-sm")
                                            warning = _module_validation_warning(row["module"])
                                            if warning:
                                                ui.label(warning).classes("sa-muted text-xs")
                                            condition_lines = [
                                                f"- `{key}`: {value}"
                                                for key, value in _module_test_options(row["module"]).items()
                                            ]
                                            scope_lines = [
                                                f"- `{key}`: {value}"
                                                for key, value in _module_scope_options(row["module"]).items()
                                            ]
                                            ui.markdown(
                                                "**Conditions**\n\n"
                                                + "\n".join(condition_lines)
                                                + "\n\n**Asset perspectives**\n\n"
                                                + "\n".join(scope_lines)
                                            ).classes("sa-muted text-sm")
                                            manifest_data = capability.get("manifest") or {
                                                "validation": {
                                                    "conditions": capability.get("conditions", {}),
                                                    "scopes": capability.get("scopes", {}),
                                                    "default_condition": capability.get("default_condition"),
                                                    "default_scope": capability.get("default_scope"),
                                                    "supports_true_positive": capability.get("supports_true_positive"),
                                                }
                                            }
                                            ui.json_editor(
                                                {
                                                    "content": {"json": manifest_data},
                                                    "mode": "tree",
                                                    "readOnly": True,
                                                    "mainMenuBar": False,
                                                    "navigationBar": False,
                                                }
                                            ).classes("w-full").style("height: 260px;")
                                        if row["module"] == "dnscap":
                                            with ui.expansion("DNScap import settings", icon="dns", value=False).classes("w-full"):
                                                ui.markdown(
                                                    "DNScap runs as a background collector. Configure which stored DNS logs this module imports into scan-assess. "
                                                    "The last-scan marker is off by default; when enabled, DNScap imports only events after the previous scan marker."
                                                ).classes("sa-muted text-sm")
                                                dnscap_module_log_root = ui.input("DNScap folder", value=state["dnscap_log_root"]).props("dense outlined").classes("w-full")
                                                dnscap_module_period = ui.select(
                                                    {
                                                        "all": "All stored logs",
                                                        "last_day": "Last day",
                                                        "last_week": "Last week",
                                                        "last_month": "Last month",
                                                        "last_year": "Last year",
                                                        "since_last_scan": "Since last scan",
                                                        "custom": "Date range",
                                                    },
                                                    label="DNScap period",
                                                    value=state["dnscap_period"],
                                                ).props("dense outlined").classes("w-full")
                                                dnscap_module_start = ui.input("DNScap start", value=state["dnscap_start"]).props("dense outlined placeholder=2026-05-27T00:00:00Z").classes("w-full")
                                                dnscap_module_end = ui.input("DNScap end", value=state["dnscap_end"]).props("dense outlined placeholder=2026-05-27T23:59:59Z").classes("w-full")
                                                dnscap_module_marker = ui.checkbox("Update last-scan marker after import", value=state["dnscap_use_last_run_marker"]).classes("sa-muted")
                                                dnscap_marker_status = ui.markdown(f"Last marker: `{state['dnscap_last_run_utc'] or 'not set'}`").classes("sa-muted text-sm")
                                                dnscap_config_surface = _module_config_surface("dnscap")
                                                if dnscap_config_surface:
                                                    with ui.expansion("Detected DNScap config files", icon="folder", value=False).classes("w-full"):
                                                        ui.markdown(dnscap_config_surface["detail"]).classes("sa-muted text-sm")

                                                def save_dnscap_from_modules() -> None:
                                                    state["dnscap_log_root"] = str(dnscap_module_log_root.value or "").strip()
                                                    state["dnscap_period"] = str(dnscap_module_period.value or "all").strip()
                                                    state["dnscap_start"] = str(dnscap_module_start.value or "").strip()
                                                    state["dnscap_end"] = str(dnscap_module_end.value or "").strip()
                                                    state["dnscap_use_last_run_marker"] = bool(dnscap_module_marker.value)
                                                    save_dnscap_runtime_config()
                                                    latest = load_module_runtime_config(MODULES_ROOT / "dnscap")
                                                    state["dnscap_last_run_utc"] = str(latest.get("last_run_utc") or "")
                                                    dnscap_marker_status.content = f"Last marker: `{state['dnscap_last_run_utc'] or 'not set'}`"
                                                    refresh_visible_llm()
                                                    ui.notify("DNScap settings saved.", type="positive")

                                                ui.button("Save DNScap settings", icon="save", on_click=save_dnscap_from_modules).props("outline dense").classes("w-full")
                                        if row["module"] == "example_module":
                                            ui.markdown("Disabled by default because it produces example/test telemetry.").classes("sa-muted")


ui.run(
    title="scan-assess workbench",
    host=os.environ.get("SCAN_ASSESS_GUI_HOST", "127.0.0.1"),
    port=int(os.environ.get("SCAN_ASSESS_GUI_PORT", "8088")),
    reload=False,
)
