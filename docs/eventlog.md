# Windows Event Log and Sysmon

The optional native subscriber uses EvtSubscribe, EvtNext, EvtRender and EvtUpdateBookmark. Accepted events and their cursor are committed in the same SQLite transaction. Inaccessible/absent channels, stale bookmarks, rendering errors and queue loss produce coverage gaps. Initial subscription starts with future events; a retained bookmark resumes after the committed provider record. Sysmon is detected but never installed automatically. Security 4624/4625 require an enabled audit policy and appropriate access; their absence cannot establish that no logons occurred.

Sysmon IDs 1/3/5/11/12–14/22 normalize process lifecycle, TCP, file creation, Registry and DNS records. Non-TCP ID 3 records and other provider IDs remain explicitly unmapped. ProcessGuid and ParentProcessGuid are preserved; Registry attribution exists only for an explicitly supplied provider PID. Native Registry snapshots have an unknown writer. Provider text does not supply native Registry bytes/type or the previous value, so those attributes remain missing.

Current-process enrichment is joined to a Sysmon start only when native creation time agrees within timestamp precision. Historical/reused PID records retain provider-only identity. Complementary verified ETW and Sysmon starts merge in persistence while each source record remains in provenance. Raw provider XML is opt-in; bounded normalized metadata is the default.

Offline import accepts a single Event XML (maximum 1 MiB) or real EVTX (maximum 100,000 normalized records), writes schema-v2 JSONL and a hash manifest, and can be replayed through the original engine:

```powershell
build/mingw/irforge.exe eventlog import --input lab.evtx --output out/import-new
build/mingw/irforge.exe replay --events out/import-new/events.jsonl --rules rules/internal --output out/replay-import-new
```

Queue drops can advance a subsequent cursor past a missing record; this is recorded as an explicit loss rather than claimed as exactly-once acquisition. Durable storage failure does not advance the corresponding committed cursor. Live Sysmon equivalence and channel-clear testing require an authorized lab with Sysmon and are separate from parser fixture validation.
