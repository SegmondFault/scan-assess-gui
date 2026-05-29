from __future__ import annotations

import json
import os
import platform
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from src.runners.run_modules import run_modules
from src.llm_profiles import LlmProfile, load_llm_profile
from src.module_config import load_module_runtime_config, module_runtime_config_path
from src.prompt_profiles import PromptProfile, load_prompt_profile
from src.scenarios import Scenario, load_scenario

from openai import OpenAI


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULES_ROOT = PROJECT_ROOT / "modules"
OUTPUTS_ROOT = PROJECT_ROOT / "outputs"
REPORTS_ROOT = PROJECT_ROOT / "reports"
LOCAL_TZ = ZoneInfo("Europe/Luxembourg")

def run_machine_info() -> dict[str, str]:
    hostname = socket.gethostname()
    return {
        "hostname": hostname,
        "platform_node": platform.node() or hostname,
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "platform": platform.platform(),
    }


def european_time_label(ts: datetime) -> str:
    return ts.astimezone(LOCAL_TZ).strftime("%d/%m/%Y %H:%M:%S %Z")


@dataclass
class RunOptions:
    demo: bool = False
    live: bool = False
    prompt_profile: str | None = None
    llm_profile: str | None = None
    scenario: str | None = None
    prompt_dev_evidence: Path | None = None


def _runtime_configured_module_dirs() -> list[Path]:
    if not MODULES_ROOT.exists():
        return []
    return [
        module_dir
        for module_dir in sorted(MODULES_ROOT.iterdir())
        if module_dir.is_dir() and module_runtime_config_path(module_dir).exists()
    ]


def apply_scenario_defaults(options: RunOptions) -> tuple[Scenario | None, list[str], bool]:
    scenario = load_scenario(options.scenario) if options.scenario else None
    notes: list[str] = []
    if scenario is None:
        return None, notes, options.demo

    notes.append(f"scenario: {scenario.name}")
    notes.append(f"scenario description: {scenario.description}")

    effective_demo = options.demo
    if not options.demo and not options.live:
        effective_demo = scenario.mode == "demo"
    if scenario.expected_findings:
        notes.append(f"scenario expected findings: {', '.join(scenario.expected_findings)}")
    return scenario, notes, effective_demo


def configure_run_mode(options: RunOptions | None = None) -> tuple[list[str], PromptProfile, LlmProfile, Scenario | None, bool]:
    """Set runner environment for the requested run path and return report notes."""
    options = options or RunOptions()
    scenario, notes, effective_demo = apply_scenario_defaults(options)
    prompt_profile_name = options.prompt_profile or (scenario.prompt_profile if scenario else None)
    prompt_profile = load_prompt_profile(prompt_profile_name)
    llm_profile = load_llm_profile(options.llm_profile)

    notes.append(f"prompt profile: {prompt_profile.name}")
    notes.append(f"LLM profile: {llm_profile.name}")
    notes.append(f"LLM model: {llm_profile.model}")
    notes.append(f"LLM base URL: {llm_profile.base_url}")
    notes.append(f"LLM context size: {llm_profile.context_size}")
    enabled_modules = os.environ.get("SCAN_ASSESS_ENABLED_MODULES", "").strip()
    notes.append(f"enabled modules: {enabled_modules if enabled_modules else 'all detected modules'}")

    if effective_demo:
        notes.append("scan-assess mode: demo")
        notes.append("module demo config: enabled")
    else:
        notes.append("scan-assess mode: live")
        notes.append("module demo config: disabled")

    runtime_config_modules = [path.name for path in _runtime_configured_module_dirs()]
    notes.append(
        "runtime-configured modules: "
        + (", ".join(runtime_config_modules) if runtime_config_modules else "none")
    )

    return notes, prompt_profile, llm_profile, scenario, effective_demo


def create_run_dirs(ts: datetime) -> tuple[Path, Path]:
    """Create output and report directories for the current run based on the timestamp."""
    date_path = Path(ts.strftime('%Y-%m-%dT%H:%M:%SZ').replace(':', '-'))

    output_dir = OUTPUTS_ROOT / date_path
    report_dir = REPORTS_ROOT

    output_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    return output_dir, report_dir


def collect_json_payload(
    json_files: list[Path], root_for_names: Path
) -> list[dict[str, str]]:
    return [
        {
            "filename": str(json_file.relative_to(root_for_names)),
            "file_data": json_file.read_text(encoding="utf-8"),
        }
        for json_file in json_files
    ]


def collect_prompt_developer_payload(evidence_path: Path, output_dir: Path) -> list[dict[str, str]]:
    raw = json.loads(evidence_path.read_text(encoding="utf-8"))
    raw_files = raw.get("files", []) if isinstance(raw, dict) else raw
    if not isinstance(raw_files, list):
        raise ValueError("Prompt Developer telemetry must be a list or an object with a 'files' list.")

    payload_files: list[dict[str, str]] = []
    for index, item in enumerate(raw_files, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Prompt Developer telemetry item {index} must be an object.")
        filename = str(item.get("filename") or f"prompt_developer/telemetry_{index}.json")
        file_data = item.get("file_data", item.get("data", {}))
        file_text = file_data if isinstance(file_data, str) else json.dumps(file_data, indent=2, sort_keys=True)
        target = output_dir / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(file_text, encoding="utf-8")
        payload_files.append({"filename": filename, "file_data": file_text})
    return payload_files


def analyze_with_llm(files: list[dict[str, str]], prompt_profile: PromptProfile, llm_profile: LlmProfile) -> str:
    if not files:
        return "No data files were generated by modules for this run."
    
    sections = [f"File: {f['filename']}\n{f['file_data']}" for f in files]
    module_prompt: str = "\n\n".join(sections)

    print("Analyzing with LLM...", flush=True)
    client = OpenAI(
        api_key=llm_profile.resolved_api_key() or "not-needed",
        base_url=llm_profile.base_url,
    )

    response = client.chat.completions.create(
        model=llm_profile.model,
        messages=[
            {"role": "system", "content": prompt_profile.system_prompt},
            {
                "role": "user",
                "content": f"{prompt_profile.user_prompt}\n\n{module_prompt}",
            },
        ],
    )

    return response.choices[0].message.content or ""


def _build_body(report_body: str, files: list[dict[str, str]]) -> str:
    file_lookup = {item["filename"]: item["file_data"] for item in files}

    def _search_variants(search: str) -> list[str]:
        """Return candidate search strings, including unescaped variants."""
        variants: list[str] = [search]

        try:
            unescaped = bytes(search, encoding="utf-8").decode("unicode_escape")
            if unescaped and unescaped not in variants:
                variants.append(unescaped)
        except UnicodeDecodeError:
            pass

        return variants

    def _render_citation(source: str, search: str) -> list[str]:
        # Look up the source file content
        content = file_lookup.get(source)
        if content is None:
            return [f"[citation] {source}: source file not found"]

        # Search for the specified string in the content
        lines = content.splitlines()
        candidates = _search_variants(search)
        match_index = None
        for idx, line in enumerate(lines):
            if any(candidate in line for candidate in candidates):
                match_index = idx
                break
        if match_index is None:
            return [f"[citation] {source}: no match for {search}"]

        # Render the matching line with context and line numbers
        start = max(match_index - 1, 0)
        end = min(match_index + 1, len(lines) - 1)
        rendered: list[str] = [f"[citation] {source}:", "```"]
        for idx in range(start, end + 1):
            rendered.append(f"{idx + 1}: {lines[idx]}")
        rendered.append("```")
        return rendered

    cleaned_lines: list[str] = []
    for raw_line in report_body.splitlines():
        # Search for citation patterns
        line = raw_line.strip()
        if line.startswith("<|") and line.endswith("|>"):
            inner = line[2:-2]
            parts = inner.split(",", 1)
            if len(parts) == 2:
                source = parts[0].strip()
                search = parts[1].strip()
                if search.startswith('"') and search.endswith('"') and len(search) >= 2:
                    search = search[1:-1]
                if source and search:
                    # Generate and display the citation for this item
                    cleaned_lines.append("")
                    cleaned_lines.extend(_render_citation(source, search))
                    cleaned_lines.append("")
        else:
            cleaned_lines.append(raw_line)

    return "\n".join(cleaned_lines).strip()


def save_report(
    ts: datetime,
    report_dir: Path,
    report_body: str,
    files: list[dict[str, str]],
    info: list[str],
    machine_info: dict[str, str],
) -> Path:
    print("Writing report...")

    cleaned_body = _build_body(report_body, files)

    report_path = (
        report_dir / f"security_report_{ts.strftime('%Y-%m-%dT%H:%M:%SZ').replace(':', '-')}.md"
    )

    header_lines = [
        "# Security Analysis Report\n",
        f"Generated (Europe/Luxembourg): {european_time_label(ts)}",
        f"Generated (UTC): {ts.isoformat()}",
    ]

    # List the parameters and provenance for the run before the LLM summary.
    header_lines.extend(["", "## Run Parameters and Provenance"])
    header_lines.append(f"- run machine: {machine_info.get('hostname', 'unknown')}")
    header_lines.append(f"- run platform: {machine_info.get('platform', 'unknown')}")
    if info:
        header_lines.extend([f"- {item}" for item in info])
    else:
        header_lines.append("- No modules executed or no files generated.")

    # List files that were included in the analysis
    header_lines.extend(["", "## Input Files"])
    if files:
        header_lines.extend([f"- {item['filename']}" for item in files])
    else:
        header_lines.append("- None")

    # Append the main report body generated by the LLM
    header_lines.extend(["", cleaned_body, ""])
    report_path.write_text("\n".join(header_lines), encoding="utf-8")

    return report_path


def save_run_manifest(
    ts: datetime,
    output_dir: Path,
    report_path: Path,
    prompt_profile: PromptProfile,
    llm_profile: LlmProfile,
    scenario: Scenario | None,
    files: list[dict[str, str]],
    info: list[str],
    machine_info: dict[str, str],
) -> Path:
    manifest_path = output_dir / "run_manifest.json"
    enabled_modules = os.environ.get("SCAN_ASSESS_ENABLED_MODULES", "").strip()
    module_runtime_config = {
        module_dir.name: load_module_runtime_config(module_dir)
        for module_dir in _runtime_configured_module_dirs()
    }
    manifest = {
        "report_path": str(report_path),
        "generated_at_utc": ts.isoformat(),
        "generated_at_local": european_time_label(ts),
        "timezone": "Europe/Luxembourg",
        "run_purpose": os.environ.get("SCAN_ASSESS_RUN_PURPOSE", "assessment"),
        "prompt_profile": prompt_profile.name,
        "llm_profile": llm_profile.name,
        "llm_model": llm_profile.model,
        "llm_base_url": llm_profile.base_url,
        "llm_context_size": llm_profile.context_size,
        "scenario": scenario.name if scenario else None,
        "enabled_modules": [item for item in enabled_modules.split(",") if item] if enabled_modules else "all detected modules",
        "module_runtime_config": module_runtime_config,
        "run_machine": machine_info,
        "module_runner_information": info,
        "input_files": [item["filename"] for item in files],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path


def run_assessment(options: RunOptions | None = None) -> Path | None:
    options = options or RunOptions()
    run_notes, prompt_profile, llm_profile, scenario, effective_demo = configure_run_mode(options)
    machine_info = run_machine_info()
    ts = datetime.now(UTC)
    output_dir, report_dir = create_run_dirs(ts) # Create output and report directories

    if options.prompt_dev_evidence:
        payload_files = collect_prompt_developer_payload(options.prompt_dev_evidence, output_dir)
        runner_info = [
            "run purpose: validation",
            f"prompt developer telemetry payload: {options.prompt_dev_evidence}",
        ]
    else:
        generated_json_files, runner_info, runner_errors = run_modules(
            MODULES_ROOT,
            output_dir,
            generic_overrides={"demo": effective_demo},
        )
        if runner_errors:
            print("\nModule Runner Errors:")
            for error in runner_errors:
                print(f"- {error}")
            print("Stopping execution due to module runner errors.")
            return None
        payload_files = collect_json_payload(generated_json_files, output_dir)
    report_body = analyze_with_llm(payload_files, prompt_profile, llm_profile)
    report_path = save_report(ts, report_dir, report_body, payload_files, [*run_notes, *runner_info], machine_info)
    manifest_path = save_run_manifest(ts, output_dir, report_path, prompt_profile, llm_profile, scenario, payload_files, [*run_notes, *runner_info], machine_info)

    print(f"\nReport saved to: {report_path}")
    print(f"Run manifest saved to: {manifest_path}")
    return report_path


def main(options: RunOptions | None = None) -> Path | None:
    return run_assessment(options)


if __name__ == "__main__":
    main()
