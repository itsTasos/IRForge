# IRForge — Lightweight Windows Endpoint Detection & Triage

IRForge v0.1 is a native C++20, local, read-only Windows 10/11 x64 console monitor. One executable collects ETW process lifecycles, IPv4/IPv6 TCP owner-PID snapshots, and Run/RunOnce/service registry changes. External JSON rules produce explainable, deduplicated incidents with process lineage and carefully qualified artifact correlation. Offline replay uses the same detection and scoring code.

**TCP polling can miss short-lived sockets. Registry notifications do not identify the writer PID. Scores are investigation priorities, not malware probabilities.**

```text
ETW process events     TCP owner-PID tables     Registry notify + typed diff
        |                      |                          |
        +----------------------+--------------------------+
                               |
                      Bounded event queue
                               |
                       Single dispatcher
                               |
              Process generations + JSON rule predicates
                               |
                 Windowed correlation + risk scoring
                               |
                Console + events.jsonl + alerts.jsonl
                    Health + session metadata
```

Build with Windows x64 MinGW-w64 GCC, CMake 3.26+, Ninja, and Git. **Visual Studio and Microsoft's separately installed Windows SDK are unnecessary**: MinGW supplies the Windows headers and import libraries. This machine already has the working compiler/toolchain under `C:\w64devkit\bin`. The portable [w64devkit 2.6.0 release](https://github.com/skeeto/w64devkit/releases/tag/v2.6.0) is the tested compiler/CMake/Ninja bundle; Git is separate. Nothing needs to be downloaded on this machine to rebuild. Live ETW normally requires an elevated console with tracing privileges. Replay, rules validation and unit tests require no administrator privileges. Linux can compile the portable core/replay; live collectors require Windows. Dependencies are nlohmann/json 3.11.3 and Catch2 3.7.1, fetched once from exact release tags and reused from the build cache. The runtime does not require Python, Catch2, or an internet connection.

```powershell
# Default: build Release and run all tests with MinGW
./scripts/build.ps1
# Optional: independent Debug build, also with MinGW
./scripts/build.ps1 -Configuration Debug
# A portable toolchain in a different directory:
# ./scripts/build.ps1 -ToolchainDirectory D:\Tools\w64devkit

# Equivalent direct Release commands, with the toolchain on PATH:
cmake --preset mingw
cmake --build --preset release --parallel 4
ctest --preset release

./build/mingw/irforge.exe --help
./build/mingw/irforge.exe rules validate --dir rules
./scripts/run_demo.ps1 -Replay
# Elevated, authorized Windows test VM:
./scripts/run_demo.ps1 -DurationSeconds 120
# Read the newest saved run, or pass -Directory out/<run-folder>:
./scripts/show_results.ps1
```

Output must be a **new or empty directory**. Each run preserves earlier logs by refusing to overwrite them. `scripts/run_demo.ps1` chooses a unique output directory. `Ctrl+C` drains the queue, flushes logs, joins collectors, and stops only this run's uniquely named ETW session. Force-kill, power loss, and console-close deadlines can prevent cleanup. `--allow-degraded` explicitly permits remaining sources to run if initialization or runtime collection fails. Without it, collection failures terminate with a nonzero status. Disabled config sources are visibly marked as reduced coverage. `--quiet` suppresses observations and alerts on stdout; coverage errors still appear on stderr.

The output folder has a protected Windows DACL granting access to the current user, SYSTEM and Administrators. Logs include full command lines and selected registry data, which may contain secrets; keep them private. `capture_command_line=false` disables capture and reduces detection coverage. No telemetry is uploaded; live collection performs no external requests and never writes monitored registry locations, terminates processes, blocks connections, installs persistence, or attempts elevation.

Example external rule (the shipped version includes additional encoded-option spellings):

```json
{
  "schema_version": 1,
  "id": "PROC-002",
  "name": "Encoded PowerShell invocation",
  "event_type": "process_start",
  "all": [
    {"field":"process.name","operator":"in_ci","value":["powershell.exe","pwsh.exe"]},
    {"field":"process.command_line","operator":"contains_ci","value":" -encodedcommand "}
  ],
  "score":25,
  "severity":"medium",
  "description":"Encoded-command indicator; suspicious in context, not proof of malicious activity."
}
```

The suspicious fixture contains an Office parent, an encoded PowerShell child, and a public TCP snapshot owned by that child's creation-time identity. Its contributions are PROC-001 +35, PROC-002 +25, NET-001 +10, and CORR-001 +30, capped at 100. The shell alone produces a high-priority score of 60, and the network chain escalates to critical. The benign notepad fixture has no alert. See [docs/sample-alert.json](docs/sample-alert.json) for an actual replay record, and [docs/implementation-report.md](docs/implementation-report.md) for executed build/test evidence.

Scores 0–19 are informational, 20–39 low, 40–59 medium, 60–79 high, and 80–100 critical. Distinct active rule IDs contribute once per incident inside the configured correlation window. Alerts emit on the first configured severity threshold and subsequent severity escalation. “Critical” suggests priority investigation, not confirmed compromise. Parent/child and owner-generation evidence supports process linkage. An identical explicit executable path supports only a weak related artifact link: registry writer remains unknown. Nearby unrelated registry changes stay standalone.

Coverage is limited to user mode, available ETW event versions, TCP polling, current user's loaded hive and HKLM Run/RunOnce in 32/64-bit views, and direct service keys' ImagePath/Start/Type values. Command lines and creation times may be unavailable, protected processes may resist enrichment, brief registry changes can be coalesced, and unknown identities cannot complete the high-confidence network chain. Public addresses, script interpreters, encoded commands, user-directory executables and automatic services all have legitimate uses. There is no packet capture, UDP remote-peer monitoring, DNS attribution, threat intelligence, or production EDR guarantee. Detailed caveats are in [docs/limitations.md](docs/limitations.md).

Each output folder contains `events.jsonl` (raw normalized observations), `alerts.jsonl` (incident threshold/escalation snapshots), `monitor-health.json` (last reported source coverage/loss counters), and `session-metadata.json` (mode, configuration, UTC interval and run result). See [reading results and current capabilities](docs/operations.md). A completed run's source health describes that recording, not a still-running monitor. Empty alerts mean no configured rule combination reached the alert threshold; they do not certify the machine clean. Incident expiration is currently maintained in memory and is not appended to the alert log as a resolution record.

Developer references: [architecture](docs/architecture.md), [rule format](docs/rule-format.md), and [testing / supervised VM procedure](docs/testing.md). CI is configured in [.github/workflows/windows.yml](.github/workflows/windows.yml) for MinGW x64 Debug and Release builds and deterministic nonprivileged CTest. CI uses the same portable toolchain release, with its download SHA256 checked. This directory has no Git remote, so no repository-specific CI badge or hosted run result can be supplied yet.

Contributions should include focused deterministic tests, truthful attribution, and updated limitations. MIT licensed; dependency licenses remain with their respective packages. v0.2 roadmap: file events, optional Sysmon intake, signatures/hashes, YARA, richer Registry/SCM views, incident timelines, and optional HTML reports.
