# Using IRForge and reading evidence

Baseline references include explicit training timestamps/version/coverage, eight bounded feature histograms (including current persistence versions and directory/hour file activity), Laplace-smoothed frequencies and low-confidence novelty/rarity context. Export/import allows validated `smoothing`, `rare_fraction` and `max_age_days` policy values; defaults are1,1% and30days. Empty, insufficient or stale references report not-ready. New histogram values stop at the byte/count budget and expose `skipped_feature_values`; training never produces a malware verdict.

Timed learning runs in the live agent after explicit opt-in: `irforge baseline learn --pipe IRForge.Agent.v1 --host HOST_GUID --duration 3600 --opt-in` (authorized administrator for pipe writes). The stored UTC deadline survives restart and the agent freezes learning at expiry; its idle checkpoint runs every five seconds. GUI learn/freeze/reset uses the same persisted control path. For a stopped recording, `irforge baseline compare --db FILE --host HOST_GUID --window 24h` compares stored observations against a frozen reference, with a visible5000-row limit and truncation flag. File-fixture learning/comparison with `--events` remains available and never starts native collection.

The CLI, Qt GUI, Windows Service and optional collector are working application components. Visual Studio is unnecessary. Run scripts/build.ps1 for the production MinGW build. Development tests, demonstrations and recordings remain local and are excluded from the release repository. See RELEASE_NOTES.md and docs/limitations.md for verification scope and external acceptance gates.

| Source / capability | What appears | Qualification |
|---|---|---|
| ETW | New/exited/existing process generations, available command line/path/parent | Requires tracing permission; protected/short-lived processes can remain partial |
| TCP4/6 | PID-generation-qualified endpoints and snapshot changes | Polling can miss short connections; direction and packet contents unknown |
| IOCP files | Create/modify/delete/rename under explicit roots | Writer unknown; overflow is visible and triggers bounded current-state reconciliation |
| Persistence | Run/RunOnce and services Registry plus SCM, tasks, Startup, IFEO/Winlogon inventories/diffs | Baselines are marked initial; actor unknown except explicit provider evidence |
| Event Log/Sysmon | Real subscription/bookmarks; Sysmon process/GUID/network/file/Registry/DNS, System7045, opt-in Security4624/4625 | Policy/channel permissions determine coverage; supported offline XML/EVTX import |
| File analysis | SHA-256, file identity changes, embedded Authenticode/cache-only revocation, approved YARA-X | Default automatic extensions are executables/scripts/archives, not personal documents; benign patterns can match |
| Detection | Original eight-rule compatibility or explicit expanded pack; Sigma subset; pinned ATT&CK | Unsupported Sigma fails; mapped techniques are behavioral context |
| Baselines / correlations | Opt-in learned/frozen host frequencies; capped contextual contributions; verified identity graphs | Rarity/reputation alone is low-confidence context |
| Investigation | Paging, filters, saved searches, time display, notes/states, cases, immutable case revisions | GUI reads local pipe; writes use explicit Windows UAC |
| Export | Offline HTML/PDF, evidence JSON, protected CSV, limited STIX2.1 and manifests/ZIP cases | No raw documents; STIX exports only supported observed objects |
| Intelligence | Reviewed JSON/CSV local SHA/IP/CIDR feeds, expiry/dedup; opt-in VT hash/public-IP lookup | No uploads; credentials/provider permission required; local quota/cache/backoff |
| Service / remote | Own visible SCM service, protected store; optional mTLS metadata spool, enrollment/revocation/scoped queries | Service and remote are optional; no remote shell or response |

Start a fresh session and connect the non-elevated GUI:

```powershell
./build/mingw/irforge.exe monitor --config config/default.json --rules rules/internal --output out/new-session --pipe IRForge.Agent.v1 --allow-degraded
./build/mingw/IRForgeUI.exe
```

Use an elevated terminal only when you want ETW or channels requiring it. --allow-degraded keeps functioning sources and visibly reports failures. Disable optional sources in configuration rather than assuming they worked. Live monitor IPC requires --pipe or ui.enabled=true; v0.1 default behavior remains compatible.

After collection stops, serve the stored evidence separately:

```powershell
./build/mingw/irforge.exe agent serve --db out/new-session/irforge.sqlite --rules rules/internal
./build/mingw/irforge.exe agent health --json
./build/mingw/irforge.exe agent query --table incidents --limit 50
```

One database has one logical owner. Query the running backend via IPC; do not open it with another CLI writer. Use the scoped incident_id returned by the database/GUI: host/session/local-ID. Legacy alerts.jsonl keeps the local ID for compatibility.

| Output | Purpose |
|---|---|
| events.jsonl | Original observations, including explicit initial snapshots and gaps |
| alerts.jsonl | Compatible historical threshold/escalation snapshots; not every evidence revision |
| monitor-health.json | Actual source states, loss/errors/drops and observation counts |
| session-metadata.json | Mode, configuration, UTC start/stop and complete/degraded/failed outcome |
| irforge.sqlite | Durable canonical events, incidents/revisions, analyst states/notes, bookmarks, cases, health |
| report folder | Selected HTML/PDF/CSV/STIX, full incident JSON, export context and manifest |
| archived-case folder and ZIP | Immutable selected revisions and their original evidence |

Read mode, coverage and loss first. Then review incident evidence identity, confidence, matched rules and explanations. A source active in a completed recording describes that run, not a process running now.

| Score | Severity | Review priority |
|---|---|---|
| 0–19 | informational | Supporting context |
| 20–39 | low | Review when context warrants |
| 40–59 | medium | Investigate evidence |
| 60–79 | high | Prompt investigation |
| 80–100 | critical | Highest triage priority |

Scores sum distinct rule IDs and clamp at100. They are not probabilities, infection labels or automatic remediation decisions. Observation analysis_state=open/expired follows the retained activity window. Separately, an analyst selects new, investigating, benign or resolved with a note. States/notes are persisted and audited; later evidence preserves the analyst decision and adds a new evidence revision. Case exports retain the exact revision selected at case creation.

```powershell
./build/mingw/irforge.exe report --db out/new-session/irforge.sqlite --incident SCOPED_ID --format pdf --output out/new-pdf-report
./build/mingw/irforge.exe export events --db out/new-session/irforge.sqlite --format json --output out/new-events
./build/mingw/irforge.exe export incidents --db out/new-session/irforge.sqlite --format csv --output out/new-incidents
./build/mingw/irforge.exe evidence verify --manifest out/new-pdf-report/manifest.json
./build/mingw/irforge.exe artifact inspect --path C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
./build/mingw/irforge.exe yara scan --rules C:/Operator/ApprovedYara --path C:/Evidence/sample.exe
./build/mingw/irforge.exe diagnostics --output out/new-diagnostics
```

Reports and exports use new directory paths (`--out` is an alias for a directory, not a single output file). Hash manifests detect modification, not authorship. Retention preserves open evidence; closed incidents become eligible after configured age. Quota exhaustion raises visible failures instead of discarding local evidence silently.

Reviewed IOC CSV header is exactly kind,value,label,expires_at. Quotes/doubled quotes and CRLF are supported; expiry may be blank. Import requires --confirm. Online keys are entered through stdin with ti credential-set --key-stdin --confirm; never use command-line keys. Credential Manager is account-specific: configuring your user key does not configure LocalSystem. Manual GUI lookups require opt-in and UAC; result jobs appear in Settings and Health.

MSI Core is selected by default; AgentService is optional and manual-start. Program Files holds binaries, ProgramData/IRForge holds protected evidence and a persistent agent-config.json. Uninstall preserves configuration/evidence. To permit GUI reading of a LocalSystem service, an administrator explicitly adds the analyst SID to ipc.allowed_reader_sids in the protected configuration and restarts IRForge. Do not broaden the DACL to Everyone. Service install/start/stop/uninstall and two-host remote setup are documented lab operations with outstanding VM validation gates.
