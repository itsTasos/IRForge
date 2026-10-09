#include "irforge/core/Config.hpp"
#include <set>
#include <stdexcept>
namespace irforge {
Config Config::load(const std::string &path) {
    auto j = readJsonFile(path);
    Config c;
    const std::set<std::string> keys = {"schema_version",
                                        "process_etw_enabled",
                                        "network_enabled",
                                        "registry_enabled",
                                        "watch_run_keys",
                                        "watch_services",
                                        "log_all_events",
                                        "capture_command_line",
                                        "network_poll_ms",
                                        "correlation_window_seconds",
                                        "context_retention_seconds",
                                        "queue_capacity",
                                        "max_history_events",
                                        "alert_min_severity",
                                        "log_directory",
                                        "file_monitor",
                                        "artifact_enrichment",
                                        "inventory",
                                        "windows_eventlog",
                                        "yara",
                                        "baseline",
                                        "storage",
                                        "ui",
                                        "threat_intel",
                                        "remote",
                                        "privacy",
                                        "ipc"};
    if (!j.is_object() || (j.value("schema_version", 0) != 1 && j.value("schema_version", 0) != 2))
        throw std::runtime_error(path + ": unsupported config schema");
    for (auto it = j.begin(); it != j.end(); ++it)
        if (!keys.contains(it.key()))
            throw std::runtime_error(path + ": unknown config field " + it.key());
    for (const auto *field : {"schema_version", "network_poll_ms", "correlation_window_seconds",
                              "context_retention_seconds", "queue_capacity", "max_history_events"})
        if (j.contains(field) && !j.at(field).is_number_integer())
            throw std::runtime_error(path + ": " + field + " must be an integer");
#define CFG(x)                                                                                               \
    if (j.contains(#x))                                                                                      \
    j.at(#x).get_to(c.x)
    CFG(process_etw_enabled);
    CFG(network_enabled);
    CFG(registry_enabled);
    CFG(watch_run_keys);
    CFG(watch_services);
    CFG(log_all_events);
    CFG(capture_command_line);
    CFG(network_poll_ms);
    CFG(correlation_window_seconds);
    CFG(context_retention_seconds);
    CFG(queue_capacity);
    CFG(max_history_events);
    CFG(alert_min_severity);
    CFG(log_directory);
#undef CFG
    const std::map<std::string, std::set<std::string>> sections = {
        {"file_monitor", {"enabled", "roots", "recursive", "max_watches"}},
        {"artifact_enrichment",
         {"hash_enabled", "signature_enabled", "max_file_mib", "workers", "queue_capacity",
          "timeout_seconds"}},
        {"inventory", {"enabled", "tasks", "startup", "services", "poll_seconds"}},
        {"windows_eventlog",
         {"enabled", "sysmon_auto_detect", "security_events_enabled", "channels", "retain_raw_xml",
          "provider_filters"}},
        {"yara", {"enabled", "rule_dir", "scan_unwatched_files", "timeout_seconds", "max_cpu_percent"}},
        {"baseline", {"enabled", "learn_only_if_opted_in", "minimum_samples"}},
        {"storage", {"backend", "retention_days", "incident_retention_days", "max_gib", "enabled"}},
        {"ui", {"enabled", "local_ipc_only"}},
        {"threat_intel", {"enabled", "provider", "file_upload", "paid_entitlement", "credential_target"}},
        {"remote", {"enabled", "collector_url", "metadata_only", "config_path"}},
        {"privacy", {"redact_command_lines_for_remote", "export_raw_evtx_only_on_request"}},
        {"ipc", {"pipe_name", "allowed_reader_sids"}}};
    for (const auto &[section, fields] : sections)
        if (j.contains(section)) {
            auto &v = j.at(section);
            if (!v.is_object())
                throw std::runtime_error(section + " must be an object");
            for (auto it = v.begin(); it != v.end(); ++it)
                if (!fields.contains(it.key()))
                    throw std::runtime_error("unknown " + section + " field: " + it.key());
            c.platform[section] = v;
        }
    auto file = j.value("file_monitor", Json::object());
    c.file_monitor_enabled = file.value("enabled", false);
    c.file_roots = file.value("roots", std::vector<std::string>{});
    c.file_recursive = file.value("recursive", true);
    c.max_watches = file.value("max_watches", 64);
    auto scan = j.value("artifact_enrichment", Json::object());
    c.hash_enabled = scan.value("hash_enabled", true);
    c.signature_enabled = scan.value("signature_enabled", true);
    auto mib = scan.value("max_file_mib", 100);
    if (mib < 1 || mib > 1024)
        throw std::runtime_error("max_file_mib must be 1..1024");
    c.max_file_bytes = static_cast<std::uint64_t>(mib) * 1024 * 1024;
    c.scanner_workers = scan.value("workers", 2);
    c.scanner_queue = scan.value("queue_capacity", 500U);
    c.scanner_timeout_seconds = scan.value("timeout_seconds", 30);
    auto inventory = j.value("inventory", Json::object());
    c.inventory_enabled = inventory.value("enabled", false);
    c.watch_tasks = inventory.value("tasks", true);
    c.watch_startup = inventory.value("startup", true);
    c.watch_scm = inventory.value("services", true);
    c.inventory_poll_seconds = inventory.value("poll_seconds", 30);
    auto log = j.value("windows_eventlog", Json::object());
    c.eventlog_enabled = log.value("enabled", false);
    c.sysmon_auto_detect = log.value("sysmon_auto_detect", true);
    c.security_events_enabled = log.value("security_events_enabled", false);
    c.retain_raw_xml = log.value("retain_raw_xml", false);
    c.eventlog_channels = log.value("channels", c.eventlog_channels);
    auto yara = j.value("yara", Json::object());
    c.yara_enabled = yara.value("enabled", false);
    c.yara_rule_dir = yara.value("rule_dir", std::string("rules/yara"));
    if (yara.contains("timeout_seconds"))
        c.scanner_timeout_seconds = yara.at("timeout_seconds").get<int>();
    c.yara_cpu_percent = yara.value("max_cpu_percent", 20);
    if (c.yara_cpu_percent < 1 || c.yara_cpu_percent > 100)
        throw std::runtime_error("yara max_cpu_percent must be 1..100 per worker");
    auto storage = j.value("storage", Json::object());
    c.storage_enabled = storage.value("enabled", true);
    if (!c.storage_enabled)
        throw std::runtime_error("durable SQLite storage is required by the extended agent");
    if (storage.value("backend", std::string("sqlite")) != "sqlite")
        throw std::runtime_error("only SQLite storage is supported");
    auto gib = storage.value("max_gib", 2);
    if (gib < 1 || gib > 16)
        throw std::runtime_error("storage max_gib must be 1..16");
    c.storage_max_bytes = static_cast<std::uint64_t>(gib) * 1024 * 1024 * 1024;
    c.event_retention_days = storage.value("retention_days", 14);
    c.incident_retention_days = storage.value("incident_retention_days", 90);
    auto ti = j.value("threat_intel", Json::object());
    c.threat_intel_enabled = ti.value("enabled", false);
    if (ti.value("provider", std::string("virustotal")) != "virustotal")
        throw std::runtime_error("configured online TI provider must be virustotal");
    if (ti.value("file_upload", false))
        throw std::runtime_error("file uploading is out of scope and cannot be enabled");
    auto remote = j.value("remote", Json::object());
    c.remote_enabled = remote.value("enabled", false);
    if (!remote.value("metadata_only", true))
        throw std::runtime_error("remote transport supports metadata only");
    if (!j.value("ui", Json::object()).value("local_ipc_only", true))
        throw std::runtime_error("endpoint UI requires local IPC");
    c.pipe_name = j.value("ipc", Json::object()).value("pipe_name", c.pipe_name);
    if (c.max_watches < 1 || c.max_watches > 64 ||
        c.file_roots.size() > static_cast<std::size_t>(c.max_watches) ||
        (c.file_monitor_enabled && c.file_roots.empty()) || c.scanner_workers < 1 || c.scanner_workers > 2 ||
        c.scanner_queue < 1 || c.scanner_queue > 500 || c.scanner_timeout_seconds < 1 ||
        c.scanner_timeout_seconds > 120 || c.inventory_poll_seconds < 5 || c.inventory_poll_seconds > 3600 ||
        c.event_retention_days < 1 || c.incident_retention_days < c.event_retention_days ||
        c.incident_retention_days > 3650 || c.eventlog_channels.size() > 16 || c.pipe_name.empty() ||
        c.pipe_name.size() > 128 ||
        c.pipe_name.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_") !=
            std::string::npos)
        throw std::runtime_error("platform resource limit outside supported range");
    for (auto &root : c.file_roots)
        if (root.empty() || root.size() > 4096)
            throw std::runtime_error("invalid watch root");
    if (c.network_poll_ms < 100 || c.network_poll_ms > 60000 || c.correlation_window_seconds < 1 ||
        c.correlation_window_seconds > 3600 || c.context_retention_seconds < c.correlation_window_seconds ||
        c.context_retention_seconds > 86400 || c.queue_capacity < 1 || c.queue_capacity > 100000 ||
        c.max_history_events < 1 || c.max_history_events > 20000)
        throw std::runtime_error(path + ": config limit outside supported range");
    if (!std::set<std::string>{"informational", "low", "medium", "high", "critical"}.contains(
            c.alert_min_severity))
        throw std::runtime_error(path + ": invalid alert_min_severity");
    if (c.log_directory.empty() || c.log_directory.size() > 4096)
        throw std::runtime_error(path + ": invalid log_directory");
    if (c.registry_enabled && !c.watch_run_keys && !c.watch_services)
        throw std::runtime_error(path + ": registry_enabled requires a watched location");
    return c;
}
Json Config::json() const {
    Json j = {{"schema_version", platform.empty() ? 1 : 2},
              {"process_etw_enabled", process_etw_enabled},
              {"network_enabled", network_enabled},
              {"registry_enabled", registry_enabled},
              {"watch_run_keys", watch_run_keys},
              {"watch_services", watch_services},
              {"log_all_events", log_all_events},
              {"capture_command_line", capture_command_line},
              {"network_poll_ms", network_poll_ms},
              {"correlation_window_seconds", correlation_window_seconds},
              {"context_retention_seconds", context_retention_seconds},
              {"queue_capacity", queue_capacity},
              {"max_history_events", max_history_events},
              {"alert_min_severity", alert_min_severity},
              {"log_directory", log_directory}};
    for (auto it = platform.begin(); it != platform.end(); ++it)
        j[it.key()] = it.value();
    return j;
}
} // namespace irforge
