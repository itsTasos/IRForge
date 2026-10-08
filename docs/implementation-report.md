# IRForge v0.1 implementation and verification report

Update on 2026-10-09: Visual Studio is no longer part of the supported default workflow. Presets, build/demo scripts, current documentation and CI now use MinGW. `scripts/build.ps1` successfully configured Release and passed **30/30 tests** (0.73 seconds). `scripts/build.ps1 -Configuration Debug` performed an independent native Debug compilation and passed **30/30 tests** (1.22 seconds), reusing already fetched dependency sources. The installed local toolchain is portable w64devkit 2.6.0 / GCC 15.2.0; no new compiler download or Visual Studio installation was needed. CI uses that pinned portable release with SHA256 verification; its hosted execution still awaits a Git remote/push.

The user's saved `out/live-20261009-005847` run was inspected on 2026-10-09. It completed approximately two minutes with ETW, TCP and Registry health all active, zero reported ETW loss/decode errors, zero queue drops and zero context evictions. It contains 336 process rundown records, 20 new process starts, 19 process exits, 257 TCP observations and 41 TCP disappearances. All process-start records have available image and command-line fields in this recording. No Registry changes or alerts were recorded. This supplies successful live ETW consumption evidence that was unavailable during the original report below; controlled Registry mutations and explicit repeated ETW session/leak checks still need VM validation. The earlier `out/live-20261009-005814` recording failed ETW startup and is clearly marked failed/degraded.

`scripts/show_results.ps1` now summarizes saved mode/session/health, event counts and the last alert per distinct incident. It was checked against the successful live run and the user's synthetic replay (two escalation alerts for one incident). Current usage and score/state interpretation are documented in operations.md. Alert expiration remains in-memory only; there is no persisted analyst resolution state or automatic whole-host infection verdict.

The dated 2026-10-08 report below is retained as historical evidence. Its MSVC/default-build instructions and statement that successful ETW was unverified are superseded by this update and the current README.

Executed on 2026-10-08 on Windows x64, OS build 10.0.26200.0. The repository initially contained only plan.md and no Git repository/remote. All milestone implementation areas A–G now exist in one C++20 CLI; verification limits below remain explicit.

| Milestone | Delivered | Verification |
|---|---|---|
| A: core/build | CMake/presets, CLI, bounded queue, variant schema, strict conversion/validation, private JSONL output, health/session metadata | Native Windows build, CLI help/version, queue/schema/config/output tests |
| B: processes | Owned unique real-time SystemTraceProvider session, TDH named-property decoding, rundown distinction, dispatcher enrichment, lifecycle generations, ETW loss query and cleanup | Compiled; lifecycle/reuse logic tested. Live StartTraceW returned Windows error 5; successful elevated ETW acceptance remains manual |
| C: network | Real AF_INET/AF_INET6 owner-PID enumeration, byte-order/scoped address normalization, baseline/state/disappearance diff, guarded generation lookup | Native dual-family loopback ownership and disappearance passed; synthetic failure/reuse/dedup cases passed |
| D: registry | Real asynchronous ancestor notifications, rearm/coalescing/reconciliation, both Run views, direct service discovery and selected typed values, null writer PID | Native Run/RunOnce/service baseline succeeded. Typed add/change/delete/service tests passed. No monitored Registry key was changed during this implementation session |
| E: rules/scoring | Six atomic external rules, two correlation rules, schema/operator/dependency validation, distinct active contributions, bounded scores | Eight rule definitions validated; positive/negative/missing-field/malformed-input tests passed |
| F: correlation/output | Same-generation network chain, verified observed lineage, weak identical-path registry artifacts, independent standalone findings, virtual replay, escalation suppression/expiration | Attribution, PID reuse, ordering, complete windows, expiration, suppression, replay determinism tested |
| G: integration/docs | Windows Debug/Release CI, build/demo/native/shutdown scripts, MIT license, README, architecture/rules/testing/limitations and actual replay samples | MinGW Release installed; graceful Ctrl+C/timed stop tested in degraded mode. MSVC configuration blocked by missing Visual Studio |

Actual toolchain: CMake 4.2.3, Ninja, MinGW-w64 GCC 15.2.0, C++20 Release. Native Windows library linkage succeeded with advapi32, tdh, iphlpapi, ws2_32 and ole32. No extra ETW import library was needed for this toolchain. MSVC compatibility is configured but remains to be verified on CI or a machine with Visual Studio 2022/Windows SDK. Exact fetched releases: nlohmann/json v3.11.3 (`9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03`) and Catch2 v3.7.1 (`fa43b77429ba76c462b1898d6cd2f2d7a9416b14`). Dependency downloads needed execution outside the restricted sandbox; the executable performs no downloads.

Build/test commands actually executed:

```powershell
cmake --preset mingw
cmake --build --preset mingw --parallel 4
ctest --preset mingw
./build/mingw/irforge_tests.exe --reporter compact
cmake --install build/mingw --prefix build/package
./build/mingw/irforge.exe --help
./build/mingw/irforge.exe rules validate --dir rules
cmake --preset msvc
```

Final Release build succeeded with no compiler warnings in the final builds. **CTest: 30/30 passed**, comprising 28 Catch2 cases plus CLI rule validation and replay. The direct Catch2 run reported **163 assertions passed**. Final CTest elapsed time was 0.92 seconds. `--help` ran and eight shipped rules validated. Installation produced `build/package/bin/irforge.exe` plus config and rules. The working executable is `build/mingw/irforge.exe` (4,021,711 bytes in this build).

`cmake --preset msvc` was actually attempted and failed with “could not find any instance of Visual Studio.” This report does **not** claim a local MSVC or Debug build passed. The configured GitHub Actions workflow has not run because this workspace has no Git remote. The initial compilation found missing MinGW TDH enum declarations, now supplied with documented schema type constants under a MinGW-only guard; all collectors then compiled and linked. There are no stub collectors or TODO-only implementation paths.

Actual replay commands:

```powershell
./build/mingw/irforge.exe replay --events tests/fixtures/suspicious_chain.jsonl --rules rules --output build/replay-final-01
./build/mingw/irforge.exe replay --events tests/fixtures/suspicious_chain.jsonl --rules rules --output build/replay-final-02
./build/mingw/irforge.exe replay --events tests/fixtures/benign.jsonl --rules rules --output build/benign-proof-01
```

Suspicious replay emitted exactly two severity escalations on one incident: high at 60 points, then critical at 100 points, with PROC-001/002, NET-001 and CORR-001 contributions. Parent event 1, child event 2 and owner socket event 3 are included as evidence. Benign replay produced zero alerts. Two final suspicious runs produced byte-identical events.jsonl and alerts.jsonl:

```text
events.jsonl SHA256 b3995163734b4cfb12c52f257e6337a678627c118fe099b2b22aab8e7a1ec531
alerts.jsonl SHA256 d7da7bebb0ba6e1eea0b5e60da95a3fa51a5e2b0ae639de8a609e0ab7e170ba5
```

Session metadata includes the chosen output directory, so its content legitimately differs across these runs. Actual captured fixture console output is in sample-output.txt; an actual final alert is in sample-alert.json. These are synthetic fixture results, not evidence of compromise on the host. A benign replay to a Unicode Greek/Chinese output path also succeeded, exercising the wide CLI and filesystem boundary. An attempted reuse of a nonempty output directory returned error 1 and preserved earlier files.

Live access checks actually executed:

```powershell
# Restricted sandbox: all three sources correctly reported access denied.
./build/mingw/irforge.exe monitor --config config/default.json --duration-seconds 5 --allow-degraded --quiet --output build/live-smoke-01
# Outside sandbox, normal host token: TCP and Registry active, ETW access denied.
./build/mingw/irforge.exe monitor --config config/default.json --duration-seconds 8 --allow-degraded --quiet --output build/live-host-01
# Default strict mode: explicit ETW access-denied diagnostic, exit 2.
./build/mingw/irforge.exe monitor --config config/default.json --duration-seconds 3 --quiet --output build/live-strict-proof-01
# Outside sandbox, read-only loopback/native and private-console shutdown probes:
./scripts/smoke_native.ps1
python scripts/smoke_shutdown.py
```

The ten-second native loopback probe opened benign local client/server sockets, observed **four established loopback rows and four disappeared rows**, and asserted both `tcp4` and `tcp6` with the probe shell's correct owning PID. Native TCP and registry baselining were active; ETW remained degraded with Windows error 5. Queue drops and context evictions were zero in the probe. Its sampled working set peaked at **10,506,240 bytes** and process CPU time totaled **0.203125 seconds** over the ten-second collection. These are measurements of one short lightly loaded run without ETW, not a throughput/EDR benchmark. Host telemetry logs remain in private, ignored build folders; only synthetic fixture output is included in distributable docs.

The private hidden-console Ctrl+C probe exited 0 within the ten-second wait bound, flushed output, and recorded stop_utc and result=degraded. Timed degraded runs also stopped cleanly. No ETW session was successfully created with this token, so these checks do **not** establish successful owned-ETW stop/restart behavior. No live Notepad/Office process capture, registry mutation, service installation, elevated ETW collection, or Windows VM acceptance test is claimed.

Remaining manual acceptance: on an authorized disposable Windows 11 VM, build MSVC Debug/Release, run elevated ETW, verify Notepad/cmd starts/exits and repeated PID generations, check zero leftover owned sessions after Ctrl+C and restart, and add/modify/delete a disposable Run value with cleanup in finally. The exact procedure and safety boundaries are in testing.md. Existing Run baseline, registry actor-null and service discovery/diff semantics already have automated/native-read coverage, but live Registry mutation notification delivery remains unverified here.

Run a supervised VM demo from the repository root in an elevated console:

```powershell
./scripts/build.ps1
./scripts/run_demo.ps1 -Executable build/msvc/Release/irforge.exe -DurationSeconds 120
```

Operational limits are detailed in limitations.md: polling/coalescing loss, null registry writer, unknown/protected process enrichment, lexical executable-path heuristics, bounded history/retention, recomputation cost and possible queue loss under load, heuristic false positives, and lack of threat intelligence or automated response. Long-running processes can lose context when their start ages out; later ownership becomes unknown rather than being attached to a stale PID. This is functional v0.1 lab software with documented limits, not production EDR certification.
