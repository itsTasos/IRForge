# IRForge v0.1 — Implementation Plan for Codex

> **Mission:** Build and ship a functional, read-only, user-mode Windows endpoint monitoring and detection CLI in **C++20**. Implement **all four capabilities together**: (1) live process monitoring, (2) process-owned network monitoring, (3) registry/persistence monitoring, and (4) configurable detection rules with cross-event correlation and explainable risk scores. Deliver a compilable project, tests, documentation, and sample output. **Do not stop after generating a scaffold.**

## 0. Operating instructions for Codex

You are the implementation agent. Treat this file as the project's primary specification.

1. **Implement the entire v0.1 scope end to end** in the current repository. Create missing files and directories as necessary. Do not produce only pseudocode, stubs, mock collectors, or TODO-only implementations.
2. Work in logical increments: core → process telemetry → network telemetry → registry monitoring → rules → correlation/scoring → persistence/logging → tests/docs. At each increment, keep the project buildable and run available tests.
3. Use current official Microsoft Learn documentation to confirm function signatures, event field layouts, ETW session configuration, supported privileges, and edge cases. Do not assume undocumented ETW payload offsets.
4. Prefer reliability and truthful attribution over spectacular alerts. Never make a claim that an API cannot substantiate.
5. If the environment is not Windows, write the complete Windows-specific code and Windows CI/test configuration, run any platform-neutral tests that can run, and **clearly report which Windows build/live tests you could not execute**. Never claim a live Windows test passed without running it.
6. Use libraries only when they genuinely reduce complexity; pin third-party dependencies to reproducible versions. Keep monitoring and OS integration native C++/Win32.
7. No destructive functions, process termination, blocking connections, registry modification, persistence installation, remote control, data uploads, or kernel drivers. **Observe, detect, explain, and log only.**
8. Finish with a clear summary of what was implemented, actual build/test commands and results, known limitations, and how to run a supervised demo on a Windows test VM.

## 1. Product definition and scope

**Project:** IRForge

**Primary platform:** Windows 10/11 x64, with Windows 11 x64 as the preferred integration-test target. Build using Visual Studio 2022 MSVC, Windows SDK, CMake and C++20. Run initially as an **interactive console application**, not a service. No GUI in v0.1.

**Capabilities required in the same working executable:**

- Receive near-real-time process start/exit events using **Event Tracing for Windows (ETW)**.
- Enumerate and diff TCP sockets with owning PIDs using the **IP Helper API**, covering **IPv4 and IPv6**. Treat the observed connection as a snapshot detection, not a packet-level or guaranteed connection-establishment event.
- Watch defined persistence-related Registry locations using **RegNotifyChangeKeyValue**, then enumerate/diff values to identify additions, changes, and deletions. Cover Run/RunOnce and relevant Windows service registry changes.
- Normalize all sources into one event model and publish via a bounded event queue.
- Load, validate, and evaluate JSON detection rules without recompilation.
- Track process identities and related observations in memory; correlate relevant events over configurable time windows.
- Produce explainable incident scores, confidence/attribution metadata, console alerts, and JSONL records.
- Support reproducible, deterministic **offline event replay**, sample fixtures, unit tests, Windows CI build, and developer documentation.

**Non-goals for v0.1:** kernel driver; behavioral machine learning; generic filesystem watch; YARA; VirusTotal; packet capture; DNS attribution; Windows firewall integration; remote collection; dashboard; Sysmon requirement; guaranteed detection of short-lived network sessions; guaranteed registry writer PID identification; automated response; scheduled task monitoring; all-user hive coverage for unloaded user profiles.

### Definition of done

From an elevated terminal in a test Windows VM, the final executable must continuously show process telemetry, observed network changes, and watched persistence modifications; match rules; combine properly linked observations into incidents; write local event/alert logs; and terminate gracefully with no ETW sessions left running. The same detection/correlation logic must also work deterministically on offline fixtures.

## 2. Architecture

```text
                    ┌───────────────────────────────┐
                    │  Windows endpoint             │
                    └──────────────┬────────────────┘
                                   │
             ┌─────────────────────┼──────────────────────┐
             ▼                     ▼                      ▼
     ProcessMonitor           NetworkMonitor         RegistryMonitor
      ETW session             IP Helper API         RegNotify + diff
             │                     │                      │
             └─────────────────────┼──────────────────────┘
                                   ▼
                       Source-specific adapters
                                   ▼
                      SecurityEvent normalization
                                   ▼
                       Bounded thread-safe queue
                                   ▼
                         Single event dispatcher
                                   │
                        ┌──────────┼──────────┐
                        ▼          ▼          ▼
                  EventStore  ProcessTracker  RuleEngine
                                   │          │
                                   └────┬─────┘
                                        ▼
                               CorrelationEngine
                                        ▼
                                   RiskEngine
                                        ▼
                          IncidentStore / AlertManager
                                        │
                               ┌────────┴────────┐
                               ▼                 ▼
                           Console         events.jsonl
                                           alerts.jsonl
```

**Important:** The primary ETW callback must do minimal work: parse/copy essential payload, enqueue, and return. Never perform slow network I/O, disk I/O, heavy JSON operations, or expensive rule evaluation on the ETW callback thread. Use a bounded queue and explicit dropped-event metrics. A single dispatcher thread is sufficient for the first release; do not introduce lock-free structures or thread pools without demonstrated need.

## 3. Project structure

```text
irforge/
├── CMakeLists.txt
├── CMakePresets.json
├── .gitignore
├── .github/workflows/windows.yml
├── LICENSE
├── README.md
├── plan.md
├── config/default.json
├── rules/
│   ├── process.json
│   ├── network.json
│   ├── persistence.json
│   └── correlation.json
├── include/irforge/
│   ├── core/{Event.hpp,EventBus.hpp,Config.hpp,Clock.hpp,Types.hpp}
│   ├── monitoring/{IMonitor.hpp,ProcessMonitor.hpp,NetworkMonitor.hpp,RegistryMonitor.hpp}
│   ├── detection/{Rule.hpp,RuleEngine.hpp,ProcessTracker.hpp,Correlator.hpp,RiskEngine.hpp}
│   └── output/{JsonlWriter.hpp,AlertManager.hpp,Metrics.hpp}
├── src/
│   ├── core/{EventBus.cpp,Config.cpp,Clock.cpp}
│   ├── monitoring/{ProcessMonitor.cpp,NetworkMonitor.cpp,RegistryMonitor.cpp}
│   ├── detection/{RuleEngine.cpp,ProcessTracker.cpp,Correlator.cpp,RiskEngine.cpp}
│   ├── output/{JsonlWriter.cpp,AlertManager.cpp,Metrics.cpp}
│   ├── replay/ReplayEngine.cpp
│   └── main.cpp
├── tests/
│   ├── test_event_bus.cpp
│   ├── test_rule_engine.cpp
│   ├── test_process_tracker.cpp
│   ├── test_correlator.cpp
│   ├── test_risk_engine.cpp
│   ├── test_registry_diff.cpp
│   ├── test_network_diff.cpp
│   └── fixtures/{benign.jsonl,suspicious_chain.jsonl,pid_reuse.jsonl,unattributed_registry.jsonl}
├── scripts/{build.ps1,run_demo.ps1}
└── docs/{architecture.md,rule-format.md,limitations.md,testing.md}
```

You may reorganize implementation files if there is a compelling technical reason, but preserve clear boundaries and document the choice.

## 4. Toolchain and dependencies

- **Language:** C++20; `/W4`, `/permissive-`, UTF-8 source, Unicode Win32 APIs, x64.
- **Build:** CMake 3.26+ with MSVC/Windows SDK; CTest for tests; Windows GitHub Actions runner.
- **Windows libraries:** `advapi32`, `tdh`, `iphlpapi`, `ws2_32` and any SDK libraries the implementation demonstrably requires. Use `sechost` where needed for ETW imports in the target SDK. Verify linker choices by compiling on Windows.
- **JSON:** nlohmann/json pinned via FetchContent or vendored exact release; do not float on `main`.
- **Tests:** Catch2 or GoogleTest pinned to an exact release. No homegrown, opaque test harness.
- **Avoid:** heavyweight UI stack, Python runtime, background service framework, elevated third-party kernel components, additional agents.

Implement Win32 handle ownership with RAII. Preserve original Windows error codes and convert to readable diagnostic messages. Treat failed API calls as explicit source-health errors rather than empty telemetry.

## 5. Canonical event model

Use a strongly typed event model with `std::variant` payloads rather than one enormous struct containing unrelated optional fields.

```cpp
using ProcessId = std::uint32_t;
using EventId = std::uint64_t;

enum class EventType {
    ProcessStart, ProcessExit,
    TcpConnectionObserved, TcpConnectionClosed,
    RegistryValueAdded, RegistryValueModified, RegistryValueDeleted,
    RegistryKeyAdded, RegistryKeyDeleted,
    MonitorStatus
};

struct ProcessIdentity {
    ProcessId pid{};
    std::optional<std::uint64_t> creationTime100ns;
    // Creation time may be unavailable; confidence then becomes lower.
};

struct ProcessPayload {
    ProcessIdentity identity;
    std::optional<ProcessId> parentPid;
    std::optional<std::wstring> imagePath;
    std::optional<std::wstring> commandLine;
    bool initialEnumeration = false;
};

struct TcpPayload {
    ProcessId ownerPid{};
    std::string protocol; // tcp4 or tcp6
    std::string localAddress;
    std::uint16_t localPort{};
    std::string remoteAddress;
    std::uint16_t remotePort{};
    std::string state;
    bool firstSnapshot = false;
};

struct RegistryPayload {
    std::wstring hive;
    std::wstring keyPath;
    std::wstring valueName;
    std::optional<std::wstring> oldData;
    std::optional<std::wstring> newData;
    std::optional<ProcessId> actorPid; // null for RegNotifyChangeKeyValue
};

using EventPayload = std::variant<ProcessPayload, TcpPayload, RegistryPayload, /* status */ std::monostate>;

struct SecurityEvent {
    EventId id{};
    EventType type{};
    std::chrono::system_clock::time_point timestampUtc;
    std::chrono::steady_clock::time_point receivedAt;
    std::string source;
    std::string host;
    EventPayload payload;
};
```

Above is a suggested contract, not a copy-paste compilation guarantee. Implement necessary include files, serialization adapters, and status-event payloads. Use consistent RFC 3339 UTC timestamps in JSONL with documented precision. Include `schema_version`, `event_id`, `event_type`, `source`, `host`, and explicit fields for absent values. Never fill unavailable data with plausible-looking guesses. Keep UTF-16 ↔ UTF-8 conversion correct and tested.

**Identity rule:** a PID is reusable. Match process context using PID **plus creation time / observed generation**, whenever available. If process start time is unknown, preserve uncertain attribution. Parent PID alone is not an immutable parent-process identity. Resolve parent image by a matching time-valid parent record, and explicitly use `unknown` when that is impossible.

## 6. Process monitoring: ETW

### Implementation requirements

1. Start a uniquely named **real-time SystemTraceProvider session** in the application's ownership, not a shared/reused global `NT Kernel Logger` session. On supported Windows use `EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE`, a unique session GUID, and enable process events with `EVENT_TRACE_FLAG_PROCESS`. Verify exact `EVENT_TRACE_PROPERTIES` sizing, string offsets, and flags against the SDK and documentation.
2. Implement ETW control and consumption with appropriate native APIs (`StartTraceW`, `OpenTraceW`, `ProcessTrace`, `CloseTrace`, `ControlTrace`) and `EVENT_RECORD` callbacks where supported. Decode event payloads by the documented event schema/TDH metadata, not by hardcoded struct offsets. Distinguish start, exit, and initial rundown/`DCStart` records.
3. Extract PID, parent PID, image name/path where available, command line where exposed by the specific event version, event timestamp, and exit code where available. The **created PID lives in the payload**, not necessarily the ETW header PID.
4. Support events with missing image path/command line. Optionally enrich using `OpenProcess` + `QueryFullProcessImageNameW` with least-required rights; expect access failures and processes that already exited. Never block event ingestion on enrichment.
5. Maintain lifecycle state and track terminated process generations. Record ETW buffer/event loss counters when obtainable, plus decoding errors.
6. On `Ctrl+C`/shutdown, close the consumer, stop **only the ETW session created by this run**, join threads and flush queues. On session collision, inaccessible privileges, or resource exhaustion, show actionable diagnostics. Do not terminate or take ownership of an unrelated ETW session.
7. The preferred live mode requires appropriate tracing privileges (run elevated for initial implementation). If ETW initialization fails, default to a **clear nonzero exit** rather than silently pretending full coverage. An explicit `--allow-degraded` mode may keep other monitors running with a visible warning.

**Process acceptance:** Launch/exit `notepad.exe` and `cmd.exe` in a test VM after IRForge starts. Observe corresponding start/exit events and valid PIDs. Initial rundown records must be marked as existing, not treated as suspicious newly created processes. Repeat launch/exit cycles to test PID generations.

## 7. Network monitoring: IP Helper snapshot diff

### Implementation requirements

1. Poll `GetExtendedTcpTable` with `TCP_TABLE_OWNER_PID_ALL` for **AF_INET and AF_INET6**, configurable interval `network_poll_ms` default **1000 ms**.
2. Use proper two-call/dynamic buffer allocation on `ERROR_INSUFFICIENT_BUFFER`, normalize IPv4 and IPv6 addresses and **network-byte-order port conversion**. Distinguish connected sockets from listening sockets. Only call it an observed outbound candidate when the row is a meaningful non-listening TCP endpoint; do not infer who initiated a connection solely from the presence of a row.
3. Diff snapshots by full endpoint key: protocol, address family, local address+port, remote address+port, owning PID, TCP state, and process generation when known. Emit events when a connection first appears and when it disappears. If a socket persists but changes state, classify it explicitly rather than duplicating arbitrary alerts.
4. On startup, label entries as `first_snapshot=true` and **do not assert they are newly established connections**.
5. Associate owning PID to a time-valid process generation, if available. Otherwise mark process identity uncertain; never confidently attach a socket to a reused PID's old process.
6. Classify IPv4/IPv6 as loopback, private/local, link-local, multicast, unspecified, or public using deterministic address logic. A public address is **not by itself a malicious indicator**. No unsupported IP reputation claims.
7. Emit `MonitorStatus` on failures. Never interpret empty results from a failing API call as “all connections closed”.
8. UDP may be omitted from v0.1: the owner-PID UDP table is endpoint/listener information and **does not show remote peers**. Do not claim UDP connection monitoring if not implemented.

**Honest limitation:** polling is only near-real-time observation, and **short-lived connections between snapshots can be missed**. Include this prominently in README and generated findings.

**Network acceptance:** While monitoring, make a benign TCP connection from a known process (e.g. to a local test HTTP server). Verify owner PID, normalized endpoint, first appearance, and removal; test both address families where available. Replay synthetic fixtures for deterministic checks.

## 8. Registry and persistence monitoring

### Scope: v0.1 monitored locations

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- Relevant 32-bit Registry views where applicable, using `KEY_WOW64_32KEY` / `KEY_WOW64_64KEY` correctly and documenting view behavior.
- `HKLM\SYSTEM\CurrentControlSet\Services` for service **key additions/deletions** and meaningful values such as `ImagePath`, `Start`, and `Type`, including new or changed service configurations. Watch scope carefully because this subtree can be noisy.

At minimum, implement Run and RunOnce completely. Implement service persistence discovery as part of the same RegistryMonitor rather than a separate SCM service scanner. Other autostart extensibility points (Winlogon, IFEO, scheduled tasks, Startup folders) are explicitly for v0.2.

### Implementation requirements

1. Open watched keys with suitable rights (`KEY_NOTIFY`, `KEY_QUERY_VALUE`, enumeration rights as needed); avoid creating missing keys solely to watch them.
2. Take a **baseline snapshot** for each key. Use `RegNotifyChangeKeyValue` with asynchronous events (`REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET`) and persistent watcher threads or correctly thread-agnostic registration. **Rearm each notification** after it fires; avoid double-arming a pending registration. Use bounded rescans/coalescing for burst activity.
3. Diff named values by name, type and raw/string representation. Support at least `REG_SZ`, `REG_EXPAND_SZ`, `REG_DWORD` and handle other types safely without invalid string assumptions. For service monitoring, enumerate subkeys and diff selected values; do not recurse unboundedly into irrelevant branches.
4. Emit added/modified/deleted events with hive, canonical path, value name, old/new typed data where readable, and observed time. Treat initial snapshot as baseline, **not an addition**.
5. If a key is deleted/replaced, close invalid handles and attempt a bounded re-open under a still-existing parent. Record lost coverage; do not spin or crash. If access is denied, report a degraded source.
6. **Registry writer attribution must be honest:** `RegNotifyChangeKeyValue` reports that something changed; it does **not** provide the PID that wrote it. Set `actorPid=null`. Never invent `actorPid` by picking whichever process ran close in time.
7. For service persistence, `Start=2` (automatic) alone is not evidence of malware. Analyze novelty, path location, selected rule predicates and context.
8. No registry writes, deletions, or automatic remediation by IRForge. Its own tests may deliberately modify a **clearly named temporary test value in a dedicated VM**, with prompt cleanup and cleanup in `finally`.

**Registry acceptance:** In a dedicated VM, add/modify/delete a disposable `HKCU\...\Run` value using a test script, verify correct before/after state and `actorPid=null`, and clean up even if a test fails. A benign service-fixture replay verifies service change detection without requiring a real service installation.

## 9. EventBus, threading, robustness

- Own one thread per active collector (with additional ETW threads only where needed), plus one event dispatcher and one asynchronous JSONL writer if necessary.
- Use a bounded mutex/condition-variable queue; no busy loops. Queue maximum configurable, default **10,000** events.
- Define queue overflow behavior (e.g. count and drop newest with unmistakable health alert); never silently discard events. Prefer preserving collector stability over indefinite blocking in ETW callbacks.
- Cancellation via `std::stop_token`/`std::jthread` where appropriate, or an equivalent safe stop mechanism; no detached unowned threads.
- Handle external termination signals / Windows console control handlers. Protect shared maps and process context against races. Apply backpressure or loss reporting to disk writer as well.
- Store event timestamps and arrival times separately. Do not assume cross-source perfect event ordering.
- Have a configurable context retention period (default **5 minutes**) and prune expired process/incident data.
- Expose diagnostics: uptime, events received by source, decode errors, ETW events lost, queue drops, registry-watch errors, snapshot failures, active incidents. Log health status periodically, but do not overwhelm console output.

## 10. External JSON rule engine

Rules are loaded from `rules/*.json` at program start. Validate schema, types, duplicate IDs, supported fields/operators, and bounded values. Bad rules must produce a meaningful location-specific validation error. Provide `rules validate` CLI command. Reject unknown operators rather than silently ignoring them. Normal event rules and multi-event correlation rules use distinct rule types.

### Example atomic event rule

```json
{
  "schema_version": 1,
  "id": "PROC-002",
  "name": "Encoded PowerShell invocation",
  "enabled": true,
  "event_type": "process_start",
  "all": [
    {"field": "process.name", "operator": "in_ci", "value": ["powershell.exe", "pwsh.exe"]},
    {"field": "process.command_line", "operator": "contains_any_ci", "value": ["-encodedcommand", "-enc "]}
  ],
  "score": 25,
  "severity": "medium",
  "description": "A scripting shell started with an encoded-command indicator. This is suspicious in context, not proof of malicious activity."
}
```

Implement a **small, well-defined expression vocabulary**: `equals_ci`, `in_ci`, `contains_ci`, `contains_any_ci`, `starts_with_ci`, and optionally `exists`. `all` = AND; `any` = OR. Document supported field paths per event type. Do not implement arbitrary code execution, scriptable predicates, or user-provided regex without guardrails. Treat absent fields as *unknown/non-match*, not empty strings that accidentally match.

Provide at least these working built-in rules, with tests:

| Rule ID | Intended signal | Default points |
|---|---|---:|
| PROC-001 | Office process starts PowerShell/cmd/wscript (verified process ancestry only) | 35 |
| PROC-002 | PowerShell/pwsh uses encoded-command option | 25 |
| NET-001 | Script process context observes a public remote TCP endpoint | 10 |
| PERS-001 | A new Run/RunOnce autorun value is observed | 20 |
| PERS-002 | New/changed Run entry references a user-writable executable path | 25 |
| PERS-003 | A new/changed auto-start service points to a user-writable executable path | 35 |

Use case-insensitive Windows executable names and carefully normalized paths. Avoid brittle literal user names, fabricated threat intelligence, and “all PowerShell is bad” logic. Document false positives and why points are heuristics, **not probabilities**.

## 11. Correlation engine

### Process context

Maintain a `ProcessTracker` keyed by PID + generation/create time (where available). Track parent/child edges, last-seen timestamps, matched detection IDs, and recently observed owned TCP endpoints. Provide a bounded time-window event history. Avoid attributing an observation from a reused PID to a previous process instance.

### Correlation types

1. **High-confidence linkage:** verified process parent/child relationships and network socket owner PID matched to the same process generation.
2. **Weak/possible linkage:** a registry persistence value references the **same normalized executable path** as a known process/descendant and occurs in a nearby time window. Describe this as *related artifact / path match*, **not** proof that the process wrote the Registry value.
3. **Unattributed registry events:** generate standalone persistence findings or host-level context. Do not merge them into an incident as if their originating process were known merely because timestamps are close.

### Example correlation rules

- `CORR-001`: Office-spawned scripting shell **AND** encoded command **AND** observed public TCP endpoint owned by the same process generation within **60 seconds**. Bonus: **+30**. Describe correlation as an observed behavioral chain, not confirmed C2.
- `CORR-002`: Suspicious process lineage **AND** a watched Run/RunOnce value whose canonical executable path matches a process in that lineage within **120 seconds**. Bonus: **+15**, confidence `low` or `medium`, explicitly note Registry writer remains unknown.

**Important:** Only add a correlation bonus when its complete conditions are met, and only once per incident per correlation rule. Correlation should be order tolerant within a configured window, because a registry notification or network snapshot may arrive after the corresponding process event. Provide tests with events arriving out of order. Context expiration and cleanup must be deterministic and testable.

## 12. Risk engine and incident model

Incidents are scored per process chain or justified shared artifact, **not per entire machine**. Store:

```text
incident_id
first_seen_utc / last_seen_utc
root_process_identity (optional)
linked_process_identities[]
event_ids[]
matched_rules[] with reasons and evidence
score 0..100
severity informational | low | medium | high | critical
confidence low | medium | high
attribution_notes[]
status open | expired
```

Suggested score thresholds:

| Score | Severity |
|---:|---|
| 0–19 | informational |
| 20–39 | low |
| 40–59 | medium |
| 60–79 | high |
| 80–100 | critical |

Score = sum of **distinct, active rule matches** + once-per-incident correlation bonuses, capped at 100. Deduplicate repeated snapshots, repeated Registry notices, and repeated alerts. Define a unique evidence key (rule ID + affected process generation or persistence artifact + bounded event window). Retain a reasoned list of score contributions; never output unexplained scores. Optional quiet/alert suppression window = **60 seconds** for repeated identical alert state, with escalation alerts permitted if severity increases.

**Crucial:** The score is a triage priority heuristic, not a validated malware probability. “Critical” means *high-priority investigation suggested*, not *confirmed compromise*.

### Example alert shape

```json
{
  "schema_version": 1,
  "alert_id": "...",
  "incident_id": "...",
  "timestamp_utc": "2026-10-08T10:00:00.000Z",
  "severity": "high",
  "score": 70,
  "confidence": "high",
  "title": "Office-launched PowerShell with network activity",
  "rule_ids": ["PROC-001", "PROC-002", "NET-001"],
  "evidence_event_ids": [101, 102, 103],
  "explanation": "Observed Office parent-child process relationship and network endpoint owned by the scripting process; external destination alone is not a malicious verdict.",
  "limitations": ["TCP snapshot polling may miss short-lived sockets"]
}
```

Use a live-incident updated alert strategy: emit on first threshold crossing and meaningful escalation; no spam of identical alert lines every polling tick.

## 13. CLI contract and output

Implement these commands:

```powershell
irforge.exe --help
irforge.exe version
irforge.exe monitor --config config\default.json --rules rules --output out
irforge.exe monitor --config config\default.json --duration-seconds 60
irforge.exe monitor --allow-degraded --output out
irforge.exe rules validate --dir rules
irforge.exe replay --events tests\fixtures\suspicious_chain.jsonl --rules rules --output replay-out
```

`monitor` runs until stopped; `--duration-seconds` is especially useful for smoke tests. `replay` uses the exact same normalization → rules → correlation → scoring path as live events, with a **virtual test clock**, no ETW session, no Registry changes, and no host mutation. Ensure deterministic IDs/order in replay mode, or stable comparable fields suitable for golden assertions.

Sample configuration:

```json
{
  "schema_version": 1,
  "process_etw_enabled": true,
  "network_enabled": true,
  "network_poll_ms": 1000,
  "registry_enabled": true,
  "watch_run_keys": true,
  "watch_services": true,
  "correlation_window_seconds": 120,
  "context_retention_seconds": 300,
  "queue_capacity": 10000,
  "alert_min_severity": "medium",
  "log_all_events": true,
  "log_directory": "out"
}
```

Output structure:

```text
out/
├── events.jsonl          # normalized observations, UTC timestamps
├── alerts.jsonl          # explainable findings / incident escalation
├── monitor-health.json   # current coverage, errors, counters
└── session-metadata.json # version, host, sources, start/stop, configuration summary
```

Write UTF-8 JSONL atomically at the line level; flush at controlled intervals and during shutdown. Protect sensitive logs with appropriate Windows ACLs / a private output folder, and warn users that full command lines and Registry values may contain secrets. No automatic uploads or external requests.

Console output should be legible (event source, event kind, PID, process name, severity, concise reason), with quiet/verbose modes if easy. Include a visibly different **DEGRADED** state when a monitor loses coverage.

## 14. Development milestones — execute all

### Milestone A: repository, build, core event pipeline

- Create CMake project, MSVC compilation presets, dependencies, Windows CI, formatting conventions.
- Implement CLI argument parsing, config validation, common event serialization, bounded EventBus, RAII/error utilities, `JsonlWriter`, `MonitorStatus` and clean shutdown.
- Unit tests: queue FIFO, overload/drop counter, graceful stop, schema serialization round-trip, invalid config.

**Exit gate:** CLI runs, `--help` works, event replay skeleton can ingest and save a test event.

### Milestone B: live ETW process monitor

- Implement ETW session controller, consumer, event decoding and enrichment, initial rundown tagging, process tracker.
- Live diagnostics for permission conflicts and ETW loss; process start/exit logging.
- Unit tests for decoded model and PID generation; supervised VM smoke test if access is available.

**Exit gate:** observe newly launched processes live and exit cleanly.

### Milestone C: network snapshots

- Implement IPv4 + IPv6 TCP owner-PID enumerator, diff engine, address classification, process association.
- First-snapshot semantics and error handling.
- Unit tests for unchanged/new/removed socket, PID reuse, state change, and API failure.

**Exit gate:** observe a benign TCP endpoint attributed to the correct PID when available.

### Milestone D: Registry/persistence watcher

- Implement Run/RunOnce watcher and relevant service subtree watcher; baseline snapshots; typed diff.
- Implement async notification rearming, rescan throttling, deletion/re-open, access errors.
- Tests for added/modified/deleted values, typed data, no false initial additions, null actor PID.

**Exit gate:** watch a disposable Run value change in a dedicated Windows VM without modifying it through IRForge.

### Milestone E: rules and scoring

- Implement rule loader, validation, field resolution, predicate evaluation, default rules, score tracking, dedup.
- Implement `rules validate` and rules documentation.
- Tests: positives/negatives, missing fields, malformed rules, case-insensitive matching, repeated observations.

**Exit gate:** rules evaluate against real/synthetic telemetry and yield transparent, bounded scores.

### Milestone F: correlation and alerts

- Implement process identity/ancestry tracking, rule match aggregation, temporal windows, high-confidence vs weak links, alert threshold/escalation, JSONL alerts.
- Deterministic `replay` path and fixtures.
- Tests: valid correlation; no cross-process false joins; PID reuse; out-of-order events; registry attribution honesty; expiration; dedup.

**Exit gate:** suspicious fixture yields a meaningful incident and benign fixture produces no high/critical alert.

### Milestone G: integration, release-quality docs and CI

- Add build/run scripts, README with architecture diagram, prerequisites, security/privacy, demo outputs, limitations and tests.
- Add `docs/architecture.md`, `docs/rule-format.md`, `docs/limitations.md`, `docs/testing.md`.
- GitHub Actions workflow: configure and compile Release + Debug (as feasible), run nonprivileged deterministic CTest suite. Do not require admin ETW access in normal hosted CI.
- Resolve compilation warnings/errors and memory/resource leaks; validate stop/restart behavior.
- Review logging behavior under privilege failures, high event volume, malformed inputs, and output-directory errors.

**Exit gate:** clean MSVC build on Windows; test suite passes; documentation reflects actual behavior; full functionality exists in one CLI executable.

## 15. Mandatory test matrix

| Scenario | Expected behavior |
|---|---|
| Benign `notepad.exe` start/exit | Correct process events; no high/critical alert |
| Two processes with same PID at different creation times (fixture) | Two separate identities; no cross-generation correlation |
| Office → shell with encoded command (fixture) | PROC-001 and PROC-002 match; explanation lists observed evidence |
| Above process with owned external TCP socket (fixture) | NET-001 and CORR-001 match once inside the time window |
| Same TCP socket in 10 consecutive polls | One first-observed event, not 10 new connections |
| Connection disappears | One closed/disappeared observation; no false process identity |
| Brief TCP session between polls | Document potential missed event; no guarantee of detection |
| Existing Run value at watcher start | Baseline only; no synthetic persistence alert |
| New Run value, writer unknown | Registry event with `actorPid=null`; no invented actor attribution |
| Run value pointing to a related executable | Optional low-confidence path-based link; explicit attribution limitation |
| Unrelated Run key change close in time to a suspicious process | Do **not** claim the process modified Registry |
| Invalid JSON and unsupported operator | Clear validation error with filename and rule ID |
| Flood of >queue capacity | Explicit drop metrics, no deadlock |
| ETW permission/session failure | Actionable error and nonzero exit, or explicitly enabled degraded mode |
| Ctrl+C in monitoring mode | Bounded graceful stop; flush logs; stop only own ETW session |
| Malformed network/registry data | Safe error; no crash or invented field |
| Out-of-order synthetic events | Same relevant incident within permitted event-time window |
| Benign replay | No high/critical incident |

Provide test fixtures and real assertions for **all** feasible pure-logic scenarios. Mark Windows elevated live tests as manual where hosted CI cannot execute them reliably. Include success/failure and environmental limitations in the final implementation report.

## 16. Security, privacy and operational constraints

- The product is a **defensive, user-consented local monitor** for the owner's machine or authorized lab. It must never attempt stealth, hiding, elevation bypass, security-product evasion, persistence installation, or mass collection from remote endpoints.
- No auto-remediation and **no modification of monitored Registry entries**.
- On startup, show active telemetry sources and collection boundaries. The tool can require administrator privileges for the ETW source; do not attempt UAC bypass.
- Avoid storing plaintext credentials intentionally. Command lines and Registry entries may unintentionally contain sensitive text; document this, restrict local file access, and optionally allow command-line capture to be disabled with an explicit detection coverage warning.
- Validate config and rule file sizes; bound string lengths, file sizes, collection buffers, memory use and event retention. Fail safely on malformed/untrusted data.
- Keep Windows API calls out of lock-held sections where feasible. Use RAII for `HANDLE`, `HKEY`, and ETW trace handles. No leaks, dangling event callbacks, or use-after-free on shutdown.
- Record exactly what coverage is active and which claims are weak. Never market the v0.1 as equivalent to a production EDR.
- Review basic load behavior and record measured CPU/memory in README or docs rather than inventing performance benchmarks.

## 17. README requirements

The repository README must contain:

1. Name/tagline: **IRForge — Lightweight Windows Endpoint Detection & Triage**.
2. What it actually does (four capabilities), requirements, precise OS/admin permissions and setup.
3. ASCII architecture diagram and data flow.
4. Build commands (CMake configure, build, CTest) and live/demo/replay commands.
5. Actual screenshots/terminal captures of a successful authorized test, if available; otherwise plainly labeled example output (no fake screenshot claims).
6. Example JSON detection rule, sample alert, risk-score explanation, and distinction between evidence vs inference.
7. Known limitations: user-mode, ETW privileges, TCP polling loss, command line availability, registry writer PID unknown, only watched persistence locations, false positives, no threat intelligence.
8. Testing instructions for a Windows VM and sample benign replay.
9. GitHub Actions CI badge once workflow is configured; license and contributing guidelines if time permits.
10. Roadmap for v0.2: file events, Sysmon intake, signatures/hashes, YARA, richer Registry/SCM views, timelines, optional HTML report.

## 18. Completion checklist for Codex

Do not declare success unless all checked items are actually implemented and verified to the extent the environment allows:

- [ ] C++20/CMake native Windows executable exists.
- [ ] ETW process start/exit collector is real, not a placeholder.
- [ ] IPv4/IPv6 TCP owner-PID diff collector is real and correctly labeled as polling.
- [ ] Registry notification + Run/RunOnce/service diff collector is real.
- [ ] Registry `actorPid` is nullable and not fabricated.
- [ ] Bounded queue and safe shutdown exist.
- [ ] External JSON rules load, validate and match events.
- [ ] Correlation supports process lineage, network ownership and honest weak Registry path linkage.
- [ ] Incidents aggregate transparent, deduplicated and bounded risk scores.
- [ ] CLI writes meaningful `events.jsonl`, `alerts.jsonl` and coverage diagnostics.
- [ ] Deterministic `replay` uses the same detection logic as live collection.
- [ ] Unit tests and fixtures cover both detections and false-positive/attribution cases.
- [ ] Windows CI builds/tests nonprivileged portions.
- [ ] README documents usage, evidence, testing, permissions, security and limitations.
- [ ] Final report accurately distinguishes tests performed from tests not performed.

## 19. Source references (official Microsoft API docs)

Use these to confirm the implementation rather than relying on this plan's code fragments alone:

- SystemTraceProvider session: https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session
- ETW process event family: https://learn.microsoft.com/en-us/windows/win32/etw/process
- Process payload and PID reuse: https://learn.microsoft.com/en-us/windows/win32/etw/process-typegroup1
- ETW controller/session guidance: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew
- Real-time ETW consumer: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew
- Consume events with ProcessTrace: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
- TCP owner-PID endpoint enumeration: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
- Async Registry change notification: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue

---

**Final instruction to Codex:** Implement **all v0.1 milestones A–G in the same pass**, not four disconnected demos. Optimize for correctness, maintainability, independently testable subsystems, and accurate analyst-facing explanations. If a feature cannot be completed or tested in the execution environment, describe the precise blocker and leave truthful implementation/status notes rather than claiming completion.
