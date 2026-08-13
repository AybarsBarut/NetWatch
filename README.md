# netwatch

**netwatch** is an open-source network diagnostics tool that provides a live packet and traffic view in the Windows terminal. It captures packets through Npcap and summarizes Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS, unencrypted HTTP, and TLS ClientHello/SNI information in a single table. It can monitor a specific device by IP address, produce basic anomaly indicators, and save captures as pcap files, Markdown logs, or JSONL sessions designed for AI agents.

> [!WARNING]
> Use netwatch only on devices you own and networks where you have explicit authorization to perform diagnostics. Capturing other people's traffic without permission may be illegal in your jurisdiction. Promiscuous mode is disabled by default and must be explicitly enabled with `--promiscuous`.

## Why netwatch?

| Feature | netwatch | Wireshark |
|---|---:|---:|
| Live packet list in the terminal | Yes | With TShark |
| One-command installation | Yes | No |
| Single self-contained executable | Yes | No |
| BPF capture filters | Yes | Yes |
| IP-focused monitoring and basic anomaly indicators | Yes | With filters and expert analysis |
| Markdown and JSONL agent sessions | Yes | Requires external processing |
| Wireshark-compatible pcap recording | Yes | Yes |
| Deep protocol analysis and GUI | Limited | Yes |

netwatch is designed for fast terminal-based diagnostics. It is not intended to replace Wireshark's full dissector and inspection capabilities.

## Quick start

Open PowerShell and run:

```powershell
irm https://github.com/AybarsBarut/NetWatch/raw/refs/heads/main/install.ps1 | iex
```

If Npcap is not installed, the installer asks for confirmation before launching the official signed Npcap installer. Windows administrator approval may be required only while installing the driver. The installer verifies the latest release executable against its SHA256 checksum and adds `netwatch` to your user PATH.

The free Npcap license does not permit silent installation, so its setup wizard must remain visible. Npcap OEM is required for silent enterprise deployment.

## Usage

```powershell
# List available interfaces
netwatch --list-interfaces

# Select an interface interactively and start capturing
netwatch

# Show HTTPS traffic on a specific interface
netwatch --interface 1 --filter "tcp port 443"

# Record traffic for a host in pcap format
netwatch --filter "host 8.8.8.8" --save capture.pcap

# Monitor a prototype device, filter HTTP traffic, and write a Markdown log
netwatch --watch-ip 192.168.1.42 --protocol HTTP --markdown-log prototype-debug.md --plain

# Show only traffic exchanged directly between two devices
netwatch --watch-ip 192.168.1.42 --peer-ip 192.168.1.50 --plain

# Show only traffic from one device to another on port 443
netwatch --source-ip 192.168.1.42 --destination-ip 192.168.1.50 --port 443 --plain

# Create a diagnostics session that an AI agent can follow live
netwatch --watch-ip 192.168.1.42 --agent-session netwatch-sessions/prototype-01 --plain

# Include up to 8 KiB of HTTP JSON/form bodies; this may expose sensitive data
netwatch --watch-ip 192.168.1.42 --protocol HTTP --include-http-body --http-body-bytes 8192 --jsonl

# Use line-oriented output for logs and pipelines
netwatch --plain --filter "udp port 53"

# Explicitly enable promiscuous mode on an authorized network
netwatch --promiscuous

# Check whether a newer release is available
netwatch --check-update

# Download and install a newer release after SHA256 verification
netwatch --update
```

Update checks use the latest published release from the canonical GitHub repository. `--update` downloads `netwatch.exe` and its matching checksum only when the remote version is newer. It verifies both the SHA256 checksum and embedded binary version, then replaces the executable after the running process exits. The previous executable is retained as `netwatch.exe.previous`.

Press `Ctrl+C` to stop a capture. BPF expressions are compiled by libpcap. Examples include `tcp`, `udp port 53`, `host 192.0.2.10`, and `net 10.0.0.0/8`.

`--watch-ip` safely adds a validated IP address to the BPF filter. Add `--peer-ip` to keep only packets exchanged directly between the watched device and one peer, in both directions. For one-way analysis, use `--source-ip`, `--destination-ip`, or both. `--port` limits the capture to packets whose source or destination matches the requested port. Peer mode and directional mode are intentionally mutually exclusive, while all scope options can be combined with a custom `--filter` and the post-capture `--protocol` filter.

For example, `--filter "tcp" --watch-ip 192.168.1.42 --peer-ip 192.168.1.50 --port 443` becomes `(tcp) and (host 192.168.1.42 and host 192.168.1.50) and port 443`. IP addresses and port ranges are validated before they are added to BPF expressions. After packet parsing, `--protocol` narrows displayed results to a comma-separated set of `HTTP`, `DNS`, `TLS`, `TCP`, `UDP`, `ICMP`, `ICMPv6`, `ARP`, and `MALFORMED`.

## HTTP and anomaly inspection

netwatch parses unencrypted HTTP/1.x requests and responses when the complete header is available in a single TCP segment. The method, target, host, status code, and headers are included in JSONL and Markdown output. Values for `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`, and `X-Auth-Token` are always written as `[REDACTED]`. HTTP body recording is disabled by default and must be explicitly enabled with `--include-http-body`. TLS payloads are not decrypted.

The following deterministic indicators are generated for a monitored device:

- Abrupt connection termination with TCP RST.
- HTTP 4xx and 5xx responses.
- Credential-bearing headers sent over unencrypted HTTP.
- A traffic spike of 500 packets within 10 seconds.
- SYN traffic from the monitored device to 12 distinct destination ports within 60 seconds.

These indicators are diagnostic hints, not proof of an attack or malfunction.

## AI agent sessions

`--agent-session <directory>` creates four stable files during a live capture:

| File | Purpose |
|---|---|
| `session.json` | Capture filter, interface, monitored/peer/directional IP scope, port, and privacy metadata |
| `events.jsonl` | One packet event per line, suitable for live following |
| `traffic.md` | A detailed traffic log readable by people and agents |
| `summary.json` | Protocol and anomaly counters written when the capture ends |

The session directory must be new or empty; netwatch never overwrites an existing session. Raw packet bytes are not included in JSONL or Markdown output. Use `--save capture.pcap` when a raw capture is also required. See [docs/AI_AGENT_GUIDE.md](docs/AI_AGENT_GUIDE.md) for the agent integration contract and command examples.

## Terminal view

```text
 No   Time             Source IP:Port          Destination IP:Port     Protocol  Length  Details
 41   14:32:08.113245  192.0.2.25:53341        1.1.1.1:53             DNS            74  Query A example.com
 42   14:32:08.127911  192.0.2.25:53342        203.0.113.10:443       TCP            66  [SYN] Seq=...
 43   14:32:08.141220  192.0.2.25:53342        203.0.113.10:443       TLS           517  Client Hello (SNI: example.com)
 44   14:32:08.152330  192.0.2.25:53343        192.0.2.50:80          HTTP          231  POST http://prototype.local/api/state
```

## Why is Npcap required?

Windows does not expose all link-layer packets directly to general-purpose user applications. Npcap provides a signed Windows driver and a libpcap-compatible API, enabling BPF filtering, loopback capture, and pcap compatibility. netwatch does not enable promiscuous mode by default.

The `--mode etw` path is reserved for future driverless metadata capture. Interface discovery works in the current preview, but live raw packet inspection requires `--mode npcap`.

## Building from source

Requirements: the .NET 8 SDK and Npcap for live capture.

```powershell
dotnet restore NetWatch.sln
dotnet test NetWatch.sln -c Release
dotnet run --project src/NetWatch.Console -- --list-interfaces
dotnet publish src/NetWatch.Console -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for architectural details.

## Releasing

Build and validate releases locally:

```powershell
.\scripts\Build-Release.ps1
```

The script reads the project version, restores dependencies, runs the Release test suite, and publishes a self-contained executable. It then verifies the executable version and documented CLI options before producing the following files under `artifacts/v<version>/`:

- `netwatch.exe` and `netwatch.exe.sha256` for the installer and self-update flow.
- `netwatch-v<version>-win-x64.zip` and its `.sha256` file for manual downloads.

Pass `-Force` explicitly to replace an existing directory for the same version.

After creating the matching `v<version>` tag, upload all four files manually to the GitHub release. This repository does not use GitHub Actions.

## Contributing

1. Create a small, single-purpose branch.
2. Add tests for behavioral changes.
3. Verify that `dotnet test NetWatch.sln -c Release` passes.
4. Document security and privacy implications in the pull request description.

Changes to packet capture code must not silently broaden default permissions, bypass user consent, or transmit captured data over the network.

## Licenses

netwatch is licensed under the MIT License. SharpPcap uses the MIT License, PacketDotNet uses MPL-2.0, and Spectre.Console uses the MIT License. Npcap is a separate product governed by its own license; this repository does not distribute Npcap binaries.
