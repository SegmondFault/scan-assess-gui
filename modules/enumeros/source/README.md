# enumeros

`enumeros` is a small Rust-based multi platform asset inventory tool for defensive security assessment.

## Standalone And scan-assess Use

Enumeros is a standalone inventory collector. It can be built and run independently to emit JSON describing host, operating-system, and browser-version metadata.

When used with scan-assess, the wrapper in `modules/enumeros/runner.py` runs or imports Enumeros output and contributes that JSON as scan-assess telemetry. scan-assess-gui discovers the module, can enable or disable it, and can show its module-owned validation telemetry options when present.

The Enumeros collector owns the inventory logic. scan-assess and scan-assess-gui consume the resulting telemetry and add report/prompt workflow around it.

In the wider telemetry suite, Enumeros answers: what host, operating-system, and browser/software versions are present, and are any of them likely to need review?

It collects basic local host metadata and prints it as JSON:

- hostname
- Windows product name
- Windows display version / release ID
- Windows build number
- installed browser versions for Chrome, Edge, and Firefox where available

## Purpose

The tool is designed for small-scale defensive security assessment and lab work. It provides a lightweight way to collect basic OS and browser version information from a Windows host without installing an agent or collecting sensitive user data.

This kind of inventory is useful for:

- identifying outdated operating system builds
- identifying outdated browser versions
- basic asset visibility
- small-organisation security reviews
- lab exercises around local enumeration and defensive telemetry

## Privacy and Scope

This tool does **not** collect:

- credentials
- documents
- browser history
- cookies
- saved passwords
- network traffic
- personal files

It only queries local OS and browser version metadata.

## How It Works

The tool uses standard Windows mechanisms:

- `reg query` for registry-based version information
- PowerShell `Get-Item` for executable product versions when registry values are unavailable
- Rust `std::process::Command` to invoke local system commands
- JSON output for downstream processing

## Example Output

```json
{
  "hostname": "DESKTOP-EXAMPLE",
  "os": {
    "product_name": "Windows 11 Pro",
    "display_version": "23H2",
    "build": "22631"
  },
  "browsers": {
    "chrome": "124.0.6367.91",
    "edge": "124.0.2478.67",
    "firefox": null
  }
}
