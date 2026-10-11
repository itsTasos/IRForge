# IRForge — Windows endpoint evidence and investigation

IRForge is a C++20 Windows 10/11 x64 preview with native collectors, durable SQLite evidence, a separate Qt desktop UI and optional authenticated multi-host collection. It observes and explains activity; it never executes remote commands, uploads files or remediates a host.

## Capabilities

- Native ETW process lifecycle, IPv4/IPv6 TCP snapshots, Registry, IOCP file changes, services/tasks/Startup inventory and Windows Event Log/Sysmon.
- Source-qualified identities and coverage, SHA-256 hashing, offline embedded PE signatures and constrained YARA-X workers.
- Explainable rules and correlations, a pinned ATT&CK subset, a documented Sigma subset, opt-in baselines and incident graphs.
- SQLite migrations, retention, analyst states/notes, cases and immutable incident revision snapshots.
- Qt investigation pages, local authenticated IPC and HTML/PDF/JSON/CSV/STIX exports with integrity manifests.
- An optional visible Windows Service, reviewed local IOC feeds, opt-in VirusTotal hash/public-IP lookup and an optional mTLS collector.

The original v0.1 CLI and schema-v1 replay remain compatible. Root `rules` retains its original eight-rule behavior; `rules/internal` explicitly enables the expanded 37-rule pack. The shipped YARA lab marker is an original harmless demonstration pattern, not a malware signature database.

## Build without Visual Studio

Use portable w64devkit 2.6.0 (GCC15), CMake/Ninja and 7-Zip. `scripts/bootstrap.ps1` restores dependencies using pinned versions and SHA-256 checksums. The supported complete application build targets Windows x64.

```powershell
./scripts/build.ps1 -Configuration Release -ToolchainDirectory C:/w64devkit
./scripts/build.ps1 -Configuration Debug -ToolchainDirectory C:/w64devkit
```

The release repository contains production source and required assets. Tests, fixtures, recordings, benchmarks and development reports remain local and are excluded from Git and distribution packages. `BUILD_TESTING` defaults to `OFF`; the optional `-Tests` build switch requires the complete separately maintained local test directory. A clean clone builds without that directory.

For direct commands, put `C:/w64devkit/bin` on PATH:

```powershell
./scripts/bootstrap.ps1
cmake --preset mingw
cmake --build --preset release --parallel 4
./scripts/deploy-runtime.ps1
```

## Run and investigate

```powershell
./build/mingw/irforge.exe version
./build/mingw/irforge.exe rules validate --dir rules/internal
./build/mingw/irforge.exe monitor --config config/default.json --rules rules/internal --output out/my-new-session --pipe IRForge.Agent.v1 --allow-degraded
```

In a second terminal, launch `./build/mingw/IRForgeUI.exe`. A live monitor already serves the local UI pipe. ETW normally requires Windows elevation; denied or disabled sources remain visibly degraded. The original default configuration enables the foundation collectors. Configure additional inventory/Event Log collection, explicit file roots, YARA, baselines and intelligence according to [operations](docs/operations.md). `config/service-msi.json` provides a schema-v2 service configuration with inventory/Event Log enabled and file/YARA/TI/remote disabled by default.

To inspect a stopped recording:

```powershell
./build/mingw/irforge.exe agent serve --db out/my-new-session/irforge.sqlite --rules rules/internal
# Launch IRForgeUI.exe in a second terminal.
```

One logical owner opens a database. Use a different `--pipe NAME` for independent sessions. The GUI stays non-elevated; analyst writes require a user-clicked Windows UAC prompt. It offers search, filtering, paging, processes, network, persistence, artifacts, rules, baselines, hosts/cases, intelligence, health and incident timelines/graphs.

Results are written to `--output`: `events.jsonl`, compatible `alerts.jsonl`, `monitor-health.json`, `session-metadata.json` and `irforge.sqlite`. SQLite preserves revisions, analyst states, notes, cases and historical evidence.

```powershell
./build/mingw/irforge.exe replay --events C:/Evidence/recording.jsonl --rules rules/internal --output out/new-replay
./build/mingw/irforge.exe report --db out/my-new-session/irforge.sqlite --incident ID --format pdf --output out/new-report
./build/mingw/irforge.exe export events --db out/my-new-session/irforge.sqlite --format json --output out/new-events-export
./build/mingw/irforge.exe evidence verify --manifest out/new-report/manifest.json
```

Scores are capped sums of distinct rules, not probabilities. Analyst states `new → investigating → benign/resolved` are manual and audited; observation activity `open/expired` is separate. No incident establishes an automatic clean/infected host verdict. Read coverage, identity, confidence and underlying evidence before drawing conclusions.

## Distribution

Python is required only to generate the MSI and audit dependency licenses. .NET/WiX is required only for MSI generation. None is an endpoint runtime dependency. Applications run offline with the DLLs shipped in the portable ZIP.

```powershell
./scripts/bootstrap.ps1 -Installer
python scripts/yara-license-audit.py
./scripts/package.ps1 -Version 1.0.0-dev
```

The package script produces a portable ZIP, genuine x64 MSI, SHA-256 checksums and corresponding-source archives in `dist`. The service feature is optional and manual-start. Evidence/configuration survive uninstall. Packages are unsigned until an owner uses `scripts/sign.ps1` with their code-signing certificate.

This is an **unsigned preview**. Local development suites passed 72 cases in Release, Debug and an instrumented build; loopback mTLS checks and a native evidence-to-GUI-to-report demonstration also passed. These are recorded local results, not hosted CI or full operational assurance. Elevated Sysmon equivalence, live VirusTotal, service/UAC/reboot, two-VM deployment and clean-machine MSI upgrade/rollback remain unvalidated.

Read [operations](docs/operations.md), [architecture](docs/architecture.md), [limitations](docs/limitations.md), [privacy](PRIVACY.md), [security](SECURITY.md), [remote deployment](docs/remote.md), [dependency notices](THIRD_PARTY_NOTICES.md) and [release notes](RELEASE_NOTES.md).
