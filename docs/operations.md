# What IRForge can observe and how to read the results

IRForge is a local read-only observation and triage CLI. It can collect process start/exit/rundown events, process-owned IPv4/IPv6 TCP endpoint snapshots and changes in selected Registry persistence locations. It combines these with eight external JSON rules, explains score contributions, correlates verified process generations and selected weak executable-path artifacts, and writes local evidence. Replay executes the same analysis against saved JSONL without running the observed commands. It does not terminate processes, block traffic, remove persistence, upload data or decide that a machine is infected.

| Source | Visible data | Important qualification |
|---|---|---|
| Process ETW | PID, parent PID, timestamp, image path/name, command line, creation time and exit code where available; existing-process baseline vs new starts | Full path/time enrichment can fail; baseline records are not new suspicious launches |
| TCP snapshots | Owning PID/known generation, IPv4/IPv6 addresses and ports, TCP state, first snapshot, state changes and disappearance | No packets, connection direction, DNS or guaranteed between-poll visibility |
| Registry | HKCU/HKLM Run/RunOnce in both views; direct service keys and ImagePath/Start/Type; additions, modifications, deletions and typed before/after values | Initial baseline is not an alert; writer PID is unknown |
| Detection | Office parent→shell, encoded PowerShell arguments, script context plus public TCP, autorun changes, commonly user-writable autorun/service paths | Heuristics with legitimate uses; public IP or auto-start alone is not malicious |
| Correlation | Office→encoded shell→same verified owner-generation network chain; suspicious lineage plus identical explicit autorun executable path | Path match is a related artifact inference, not proof of Registry writer |

Build and test with `./scripts/build.ps1`; optionally add `-Configuration Debug`. Both use the already installed MinGW toolchain. `./scripts/run_demo.ps1 -Replay` runs a harmless synthetic example. `./scripts/run_demo.ps1 -DurationSeconds 120` runs the compiled Release monitor with a unique output folder; ETW normally needs an administrator console.

Results live in the chosen `--output` directory. The demo script chooses `out/demo-<UTC timestamp>-<suffix>` and prints the path. Existing folders with contents are never overwritten. `./scripts/show_results.ps1 -Directory out/<folder>` reads a specific recording. Without `-Directory`, it selects the most recently written saved run under out and prints its mode, coverage, event counts, and last alert per incident. The helper only reads files.

| File | What to use it for |
|---|---|
| events.jsonl | Find raw observations and join `event_id` to alert evidence IDs |
| alerts.jsonl | See threshold crossings/escalations, rule IDs, points, reasons, score, confidence, process identities and attribution limits |
| monitor-health.json | Check whether sources were active/degraded, errors, ETW loss, queue drops and context evictions; see number of currently retained incidents at the last write |
| session-metadata.json | Distinguish live vs replay, find configuration and UTC start/stop times, and see complete/degraded/failed run result |

Read results in this order: first mode and session completion, then coverage/loss, then incident evidence/score/confidence. Logs use UTC; Athens local time on 2026-10-09 is three hours later. A source marked active in a completed recording describes coverage during that run, not a running process now. A missing stop timestamp alone does not prove a monitor is still running; abrupt termination can leave incomplete metadata.

| Incident score | Severity | Suggested triage interpretation |
|---|---|---|
| 0–19 | informational | Context to retain |
| 20–39 | low | Review if unexpected |
| 40–59 | medium | Investigate the process/artifact and evidence |
| 60–79 | high | Prioritize investigation |
| 80–100 | critical | Urgent investigation suggested; still not confirmed compromise |

These are priorities per process chain or justified shared artifact, not per whole machine. Default alert threshold is medium (40). A single new Run value scores 20 and a service-path finding scores 35, so they may be visible only in events/context unless the threshold is lowered or other matching evidence raises the score. Each distinct active rule contributes once, plus complete once-per-rule correlation bonuses, capped at 100. Confidence describes strength of linkage: known creation times/ancestry can support high confidence; unknown ownership or a Registry path-only link reduces it. A high score with low confidence still needs attribution checks.

The synthetic suspicious replay contains one incident that first alerts at 60 (35 Office→shell +25 encoded argument), then escalates to 100 (+10 script/public TCP +30 complete same-process correlation). Two alert lines are escalation records for that one incident. Both are synthetic fixture findings, not detections on this machine.

Lifecycle status is separate from severity. `open` means active evidence exists in the retained correlation context. `expired` means that evidence aged out of the analysis window; it does not mean remediation happened. Currently expiration is in memory only: alerts.jsonl stores snapshots emitted at threshold crossing/escalation and does not append expiration/resolution records. There is no analyst case state such as confirmed/dismissed/resolved and no persisted whole-host safe/infected state. Treat an empty alert log as “no alert reached the configured threshold in the observed interval,” not a clean-machine certificate, especially if coverage was degraded.

Current recorded host evidence (reviewed 2026-10-09): `out/live-20261009-005847` completed approximately two minutes with all sources reporting active, zero reported ETW loss/decode errors, zero queue drops and zero context evictions. It contains 356 process-start records: 336 existing-process rundown entries and 20 new starts, plus 19 exits. TCP records include 257 observations and 41 disappearances. No Registry changes or alerts were recorded; registry baselining succeeded. An earlier `out/live-20261009-005814` failed ETW startup with access denied; that incomplete run is not evidence of full monitoring. `out/replay-20261009-005756` is the synthetic 60→100 escalation example.

Remaining work is mainly validation/hardening: Registry notification delivery for controlled mutations in a dedicated VM; explicit repeated ETW session restart/leak checks; longer high-volume and disk-error testing; longer-lived process context without retaining every event; stronger path/argument normalization; rule tuning; and a persisted incident-state journal. GitHub CI needs a remote/push before a hosted result exists. Future optional capabilities include a timeline/HTML report, hashes/signatures, file events, additional persistence locations, Sysmon intake and YARA. None of those are current capabilities.
