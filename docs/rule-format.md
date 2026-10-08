# JSON rule format, schema version 1

Each sorted `rules/*.json` file contains one object or an array. Files are at most 1 MiB; at most 256 files and 512 rules load. IDs must be unique, nonempty and at most 64 bytes. Unknown top-level fields, schema versions, event types, field paths, operators, dependencies and invalid value types fail validation with filename and rule ID. Descriptions are at most 4096 bytes, names 256, scores 0..100. Use `irforge rules validate --dir rules` before monitoring. Rule loading performs no code evaluation, regex, scripts or external requests.

Atomic event rule fields: schema_version, id, name, description, severity, enabled (default true), type (default event), event_type (one canonical name or array), all and/or any, score. Severity is a descriptive hint; final incident severity comes from the score. `all` requires every predicate; `any`, when nonempty, requires one. Both groups must pass when present. Each has at most 32 predicates. Missing fields never match, including contains and exists. Initial process rundown bypasses atomic process detections.

A predicate contains `field`, `operator`, `value`. `equals_ci`, `contains_ci`, `starts_with_ci` accept nonempty strings up to 4096 bytes. `in_ci` and `contains_any_ci` accept 1..64 nonempty strings. `exists` accepts no value and matches only an available field. Values are compared case-insensitively using Windows invariant lowercase. On other platforms the portable fallback case-folds ASCII; replay on Windows is the primary target. Derived booleans and DWORD fields compare against strings such as `"true"` and `"2"`.

| Field | Event family | Meaning |
|---|---|---|
| process.name | Process, TCP | Executable basename from event or time-valid owner context |
| process.image_path | Process, TCP | Available image path |
| process.command_line | Process | Captured command line, otherwise unavailable |
| process.parent.name | Process, TCP | Verified time-valid parent image, otherwise unavailable |
| process.initial_enumeration | Process | true for existing/rundown records |
| network.remote_class | TCP | public, private_local, loopback, link_local, multicast, unspecified, reserved, invalid |
| network.state | TCP | Native TCP state name, lowercase comparison |
| network.first_snapshot | TCP | Whether observation belongs to the baseline |
| network.change | TCP | appeared, state_changed, disappeared |
| network.owner_verified | TCP | Creation time matches the resolved owner generation |
| registry.is_run | Registry | Canonical CurrentVersion Run or RunOnce key |
| registry.is_service | Registry | Direct service configuration under CurrentControlSet Services |
| registry.new_data | Registry | Decoded REG_SZ/REG_EXPAND_SZ text, otherwise unavailable |
| registry.user_writable | Registry | Explicit executable path under Users or a Temp directory; lexical heuristic |
| registry.service_start | Registry | Current selected service Start DWORD, if available |
| registry.actor_known | Registry | false for all native registry observations |

Canonical event names: process_start, process_exit, tcp_connection_observed, tcp_connection_closed, registry_value_added, registry_value_modified, registry_value_deleted, registry_key_added, registry_key_deleted, monitor_status. The `payload` variant and JSON shape are defined in Event.hpp / Event.cpp; explicit absent values serialize as null. Registry raw bytes remain in JSON arrays even when text or DWORD representations exist.

Correlation rules use type=correlation, requires (2..16 atomic rule IDs), linkage (`same_process` or `lineage_path`), window_seconds (1..3600), and the common identity/name/description/score/severity/enabled fields. They do not have event_type or all/any. All dependencies must exist as atomic rules. Disabled dependencies cannot contribute. The configured active correlation window additionally limits available evidence; increasing a rule window past it cannot extend retention. All required observations must fit one complete event-time window. `same_process` verifies one process generation and known TCP owner identity; `lineage_path` also requires weak same-path artifact evidence in that incident. Repeated matches contribute once per rule ID per incident, regardless of socket count or polling cadence.

Built-ins are heuristics: PROC-001 Office→shell +35; PROC-002 encoded PowerShell option +25; NET-001 script plus public established TCP snapshot +10; PERS-001 new autorun +20; PERS-002 new/changed autorun under a user-writable path +25; PERS-003 new/changed auto-start service under a user-writable path +35. CORR-001 complete same-process chain within 60s adds 30; CORR-002 suspicious lineage and same-path new autorun within 120s adds 15. NET-001 suppresses baseline sockets. Rule predicates for encoded arguments are bounded substring indicators, not a complete PowerShell argument parser; see limitations.
