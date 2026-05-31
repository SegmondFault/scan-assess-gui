# SafeSniff

SafeSniff is a Rust-based network-observation and safe TCP-enumeration tool for defensive assessment. It is intended for owner-authorised environments and can be built as standalone binaries for multiple operating systems and CPU architectures.

## Standalone And scan-assess Use

SafeSniff can be run independently from its Rust source or from one of the release binaries in `bin/`.

When used with scan-assess, the wrapper in `modules/safesniff/runner.py` selects the appropriate platform binary where available, runs the configured SafeSniff mode, and writes JSON telemetry into the current scan-assess output directory. scan-assess-gui discovers the module, can enable or disable it, and can show its module-owned validation telemetry options.

SafeSniff owns network target detection and service-enumeration behaviour. scan-assess and scan-assess-gui consume the resulting telemetry and must preserve the distinction between target detection and active TCP service scans.

In the wider telemetry suite, SafeSniff answers: what network devices or exposed services are observable in an owner-authorised environment, and how risky are they?

## Multi-Platform Binaries

The imported module expects binaries under `bin/` using these names:

- `safesniff-macos-arm64`
- `safesniff-macos-x64`
- `safesniff-linux-arm64`
- `safesniff-linux-x64`
- `safesniff-windows-x64.exe`

See `BUILDING.md` for rebuild notes.

## Runtime Configuration

The scan-assess wrapper reads runtime settings from `config/scan_assess_runtime.json` and supports module-owned demo/validation telemetry. If no matching binary is available, the wrapper can fall back to running the Rust source with Cargo when the source manifest is present.
