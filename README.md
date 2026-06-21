# scan-assess-gui

This is a gui frontend for scan-asses, a local framework that runs security collection modules, passes their JSON outputs to a local OpenAI-compatible LLM endpoint, and writes a Markdown security report. The GUI version introduces a lot of concepts like prompt/LLM validation via dummy telemetry, context usage estimation, and evidence navigation. As such, it's very much a working POC, that needs thorough testing, validation before deployment in a security-sensetive context.

## Visual Preview

![scan-assess workbench reports view](docs/screenshots/workbench.jpg)

## Run The LLM Server

Optionally, with llama.cpp, in one terminal:

```bash
./launch_llama.sh
```

The scanner expects an OpenAI-compatible endpoint at:

```text
http://localhost:8033/v1
```

## Run scan-assess

Install dependencies:

```bash
uv sync
```

Official/live path:

```bash
uv run python main.py --live
```

Demo path, including the bundled phishing-DNS scenario and demo ThreatSucker intel:

```bash
uv run python main.py --demo
```

DNScap log folders and time windows are configured inside the DNScap module:

```text
modules/dnscap/config/scan_assess_runtime.json
```

The DNScap wrapper imports stored collector logs for the configured window, such as all logs, last week/month/year, since the previous successful scan-assess DNScap import, or a custom date range.

Select a model endpoint/profile:

```bash
uv run python main.py --live --llm-profile local-llamacpp
```

Reports are written to `reports/`. Module outputs are written to `outputs/`.

## Run The GUI Workbench

```bash
uv run python -m src.gui_app
```

Open:

```text
http://127.0.0.1:8088
```

The GUI workbench provides assessment launching, output location preview, prompt-profile editing, prompt validation, LLM-profile selection, detected-module enable/disable switches, a first-class Reports view, report-to-evidence links, and a module-folder Evidence browser with beautified JSON/JSONL/text viewing.

Prompt experiments live in the **Prompt Developer** tab. That view puts the selected scenario, system prompt, user prompt, validation, per-module test choices, editable evidence payload, and the run-again button on the same screen. Module choices regenerate the JSON payload, and you can edit the JSON directly afterwards. `Run Prompt Check` uses that edited evidence directly, without sending scenario names or expected-findings labels to the LLM.

The left sidebar keeps assessment setup folded away by default. Open **Run setup** to choose or edit the prompt profile and LLM profile, including the model name, OpenAI-compatible base URL, API-key environment variable, and description.

When a run completes, module evidence appears under:

```text
outputs/<run>/<module>/
```

The matching Markdown report appears under:

```text
reports/security_report_<run>.md
```

Prompt profiles live in `config/prompt_profiles/`. Scenario packs live in `config/scenarios/`. LLM profiles live in `config/llm_profiles/`.

## Imported Modules

- `modules/enumeros`: live local host/software/browser inventory.
- `modules/safesniff`: conservative target detection by default; active scans require opt-in.
- `modules/dnscap`: DNScap DNS log importer.
- `modules/threatsucker`: explainable threat-intel correlation over module outputs.

## ThreatSucker UI

```bash
cd modules/threatsucker/source
uv run threatsucker web --host 127.0.0.1 --port 8765
```

Open:

```text
http://127.0.0.1:8765/config
```

The config UI provides source toggles, source import, scoring sliders, YAML validation, and raw YAML editing.

## Safety Notes

- Bundled phishing DNS logs are only used by `--demo` or when configured in `modules/dnscap/config/scan_assess_runtime.json`.
- Bundled demo ThreatSucker intel is excluded from official scan-assess runner workspaces unless `--demo` is used or `modules/threatsucker/config/scan_assess_runtime.json` enables it.
- Prompting is provenance-aware: sample/demo data is excluded from action items, imported DNS logs are treated as historical observations, and SafeSniff target detection is not described as a TCP service scan.
