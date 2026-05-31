# dnslog-agent

`dnslog-agent` is a lightweight local DNS logging agent for defensive telemetry. It runs as one transparent background program per host and writes local structured JSON Lines logs for later analysis by separate tools, including LLM pipelines. CSV output is available with `--format csv`.

Project label: CNS cab.

## Standalone And scan-assess Use

DNScap/dnslog-agent is a standalone Rust project. It can be built, installed, and run independently as a local DNS logging agent or LAN collector without scan-assess.

When used with scan-assess, the wrapper in `modules/dnscap/runner.py` imports DNScap JSONL/CSV logs and converts the selected time window into scan-assess telemetry. The scan-assess GUI reads the module runtime configuration exposed by that wrapper so an operator can choose the log folder, import period, custom date range, and optional last-run marker from the Modules page.

The Rust agent owns DNS collection. scan-assess and scan-assess-gui only consume the resulting telemetry; they do not replace the background collector.

In the wider telemetry suite, DNScap answers: what DNS activity has been observed for this host or network, and over what time window?

## What It Captures

The agent captures observable classic DNS traffic over UDP/TCP port 53 using a local packet capture handle and this BPF filter:

```text
udp port 53 or tcp port 53
```

It parses DNS query names and query types from packets visible to the host capture interface.

## What It Does Not Capture

`dnslog-agent` does not capture DNS-over-HTTPS, DNS-over-TLS, DNS inside VPN tunnels, encrypted browser DNS, or traffic hidden from local packet capture. That limitation is intentional for v1.

## Local Logs Only

In `single` mode, logs stay on the host for privacy and simplicity. In `client` mode, forwarding is limited to a configured LAN host and is disabled unless explicitly configured. Client-to-host forwarding is encrypted with AES-256-GCM using the configured `shared_token` as pre-shared secret material. The agent does not perform enrichment, threat analysis, alerting, reverse DNS lookups, threat-intel API calls, internet upload, or sync to a central cloud service.

The intended service posture is visible but unobtrusive: a normal Windows Service, launchd job, or systemd unit with a clear service name and local health log. It should be easy for an operator or end user to confirm that it is running, and equally easy for a deployer to stop or remove it.

## Build And Release Artifacts

For local development:

```sh
cargo build --release
```

For distributable Linux, macOS, and Windows artifacts, see [BUILDING.md](BUILDING.md). The recommended Linux release path is Docker so the libpcap build environment is reproducible.

See [TESTING.md](TESTING.md) for the host/client validation flow.

## Quick Start

Run one host as the collector, then run one agent on each client machine. The examples below use:

```text
Collector: 192.168.1.10:53530
Clients:   192.168.1.0/24
```

JSON Lines is the default output format. Add `--format csv` to `run` or `once` to write CSV files instead.

### 1. Generate A Shared Token

Generate one token and use the same value in the host and client configs:

```sh
openssl rand -base64 32
```

### 2. Create The Host Config

Create `host.toml` on the collector:

```toml
[storage]
root = "./logs"
format = "json"

[capture]
interface = "auto"

[agent]
mode = "host"

[collector]
listen_addr = "0.0.0.0:53530"
shared_token = "paste-the-generated-token-here"
allowed_subnets = ["192.168.1.0/24"]
```

Validate it:

```sh
./dnslog-agent validate-config --config host.toml
```

Start the collector:

```sh
sudo ./dnslog-agent run --config host.toml
```

### 3. Create The Client Config

Create `client.toml` on each client:

```toml
[storage]
root = "./logs"
format = "json"

[capture]
interface = "auto"

[agent]
mode = "client"

[client]
collector_addr = "192.168.1.10:53530"
shared_token = "paste-the-same-generated-token-here"
source_id = "auto"
```

Validate it:

```sh
./dnslog-agent validate-config --config client.toml
```

Start the client:

```sh
sudo ./dnslog-agent run --config client.toml
```

On Windows, use Administrator PowerShell:

```powershell
.\dnslog-agent-x86_64-pc-windows-gnu.exe run --config .\client.toml
```

### 4. Verify Logs

On the collector, remote client logs are written under:

```text
logs/remotehost-<source-id>-<peer-ip>/YYYY/MM/DD/dns.jsonl
logs/remotehost-<source-id>-<peer-ip>/YYYY/MM/DD/health.jsonl
```

Generate classic DNS traffic from a client:

```sh
nslookup example.com
```

Then check the collector:

```sh
find logs -type f -maxdepth 8 | sort
```

```sh
grep -R '"qname":"example.com"' logs
```

### Operational Checks

List capture interfaces:

```sh
./dnslog-agent interfaces
```

Confirm classic DNS is visible on Linux:

```sh
sudo tcpdump -ni any 'udp port 53 or tcp port 53'
```

Confirm a client can reach the collector:

```sh
nc -vz 192.168.1.10 53530
```

Keep client clocks correct. Log files rotate by the event date, so a bad clock can make fresh traffic appear under the wrong day:

```sh
date
sudo timedatectl set-ntp true
```

### Windows Runtime Dependency

Windows requires [Npcap](https://npcap.com/#download). Install it before running the agent and enable **WinPcap API-compatible Mode** if the installer offers it.

Check for Npcap in Administrator PowerShell:

```powershell
Test-Path C:\Windows\System32\Npcap\wpcap.dll
Test-Path C:\Windows\System32\wpcap.dll
```

If the Windows binary exits immediately and `$LASTEXITCODE` is `-1073741515`, a required DLL is missing. Install or repair Npcap, then open a fresh Administrator PowerShell.

## List Interfaces

```sh
./target/release/dnslog-agent interfaces
```

## Run

```sh
sudo ./target/release/dnslog-agent run --config config.example.toml
```

To write CSV instead of the default JSON Lines output:

```sh
sudo ./target/release/dnslog-agent run --config config.example.toml --format csv
```

For a short test run:

```sh
sudo ./target/release/dnslog-agent once --config config.example.toml --seconds 30
```

## Test DNS Capture

In another terminal, generate classic DNS traffic:

```sh
nslookup example.com
dig example.com
```

## Output Layout

Daily JSON Lines files are written under the configured storage root by default:

```text
logs/
  localhost/
    2026/
      05/
        02/
          dns.jsonl
          health.jsonl

  remotehost-laptop-01-192-168-1-44/
    2026/
      05/
        02/
          dns.jsonl
          health.jsonl
```

`localhost` contains DNS observed on the current machine. In `host` mode, remote clients are stored under sanitized `remotehost-<source-id>-<peer-ip>` folders. The host also captures from itself.

Example `dns.jsonl`:

```json
{"ts":"2026-05-02T10:31:22.123Z","host":"laptop-01","os":"macos","interface":"en0","src_ip":"192.168.1.44","dst_ip":"1.1.1.1","src_port":55321,"dst_port":53,"proto":"udp","qname":"example.com","qtype":"A"}
```

Example `health.jsonl`:

```json
{"ts":"2026-05-02T10:35:00.000Z","event":"health","captured_packets":1000,"parsed_dns_queries":940,"parse_errors":3,"dropped_events":0,"queue_depth":0}
```

Use `--format csv` on `run` or `once`, or set `storage.format = "csv"`, to write `dns.csv` and `health.csv` with the same fields.

## Configuration

See [config.example.toml](config.example.toml).

The agent supports three operating modes:

- `single`: capture this device and write local logs only.
- `client`: capture this device, write local logs, and forward copies to a configured LAN host.
- `host`: capture this device, write local logs, and receive client events from the LAN.

Default config paths when `--config` is omitted:

- Linux: `/etc/dnslog/config.toml`
- macOS: `/Library/Application Support/dnslog/config.toml`
- Windows: `C:\ProgramData\DnsLog\config.toml`

Validate and print resolved defaults:

```sh
./target/release/dnslog-agent validate-config --config config.example.toml
```

Generate a host-mode config interactively:

```sh
./target/release/dnslog-agent configure-host --output host.config.toml
```

## Performance Model

- Kernel BPF filter limits packets before user-space parsing.
- Capture and writing are separated by a bounded channel.
- The writer appends one JSON object or CSV row per event and uses buffered file writes.
- Log files rotate by local date.
- If the queue is full, events are dropped and counted.
- Disk writes do not block packet capture.
- In `client` mode, LAN forwarding uses a separate bounded queue. Collector outages do not block local capture or local logging.
- Compression is intentionally omitted from the hot path in v1.

## LAN Host And Client Mode

For multi-device setups, run one visible agent on each endpoint. Clients capture their own local DNS and forward copies to a configured LAN host. The LAN host captures from itself and listens for authenticated client events.

This is not subnet-wide packet sniffing. On switched networks, one machine normally cannot see other hosts' DNS traffic anyway, and endpoint clients give a cleaner reliability and visibility model.

Example client config:

```toml
[agent]
mode = "client"

[client]
collector_addr = "192.168.1.10:53530"
shared_token = "generate-a-fresh-32-byte-random-token"
source_id = "auto"
```

`collector_addr` may be an IP address or a resolvable LAN hostname:

```toml
[client]
collector_addr = "dnslog-host.local:53530"
```

For DHCP-heavy networks, prefer a DHCP reservation or stable local DNS/mDNS name for the host. The agent does not scan subnets to find collectors.

Example host config:

```toml
[agent]
mode = "host"

[collector]
listen_addr = "0.0.0.0:53530"
shared_token = "generate-a-fresh-32-byte-random-token"
allowed_subnets = ["192.168.1.0/24"]
max_clients = 128
max_frame_bytes = 1048576
read_timeout_seconds = 30
```

Host mode requires `allowed_subnets` to be explicit. Use `configure-host` during deployment to generate a fresh `shared_token`, or set the CIDR ranges and token directly in the config. Use a long random `shared_token`; it is used to derive the AES-256-GCM key for LAN forwarding. Placeholder tokens and short tokens are rejected in client and host modes.

When deploying clients, point `collector_addr` at the host by IP or name. Names are resolved by the operating system, so `dnslog-host.local:53530` works when mDNS/local DNS is configured on the network.

## LAN Forwarding Encryption

Client-mode forwarding is encrypted on the LAN. Each event is serialized, encrypted with AES-256-GCM, and sent as one JSON frame containing:

```text
version, alg, nonce, ciphertext
```

The DNS event contents, source host, and source ID are inside the ciphertext. The configured `shared_token` is never sent over the wire in plaintext. Anyone who captures the LAN traffic can see that clients are connecting to the host, but not the DNS event contents without the shared token.

## Privileges

Linux and macOS usually require elevated privileges or capture-specific permissions for packet capture.

Windows requires [Npcap](https://npcap.com/#download) at runtime. Install Npcap before running the agent, and enable **WinPcap API-compatible Mode** if the installer offers it. The Windows binary depends on Npcap's `wpcap.dll`; without it, Windows may start and immediately exit with no output. In PowerShell, this often appears as:

```powershell
$LASTEXITCODE
-1073741515
```

That code is `0xC0000135`, which means a required DLL is missing. Check for Npcap with:

```powershell
Test-Path C:\Windows\System32\Npcap\wpcap.dll
Test-Path C:\Windows\System32\wpcap.dll
```

After installing Npcap, open a new Administrator PowerShell and verify:

```powershell
.\dnslog-agent-x86_64-pc-windows-gnu.exe --help
.\dnslog-agent-x86_64-pc-windows-gnu.exe interfaces
```

## Service Templates

Print a Linux systemd template:

```sh
./target/release/dnslog-agent service-template --target linux
```

Print a macOS launchd template:

```sh
./target/release/dnslog-agent service-template --target macos
```

Print Windows service notes:

```sh
./target/release/dnslog-agent service-template --target windows
```

## Safety And Non-Goals

This project is logs only. It does not modify packets, spoof DNS, intercept traffic beyond passive local capture, hide itself, install persistence tricks, perform C2 detection, detect phishing, upload data to the internet, or contact remote enrichment services. Optional `client` mode can forward encrypted copies of local log events to a configured LAN host.

## Current Limitations And TODOs

- Better TCP DNS handling with stream reassembly.
- Windows service implementation.
- Optional response logging.
- Resolver config snapshot.
- Optional compression after rotation.
- Process attribution as a future platform-specific extension.
