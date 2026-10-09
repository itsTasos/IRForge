#pragma once
#include "Event.hpp"
namespace irforge {
struct Config {
    bool process_etw_enabled = true, network_enabled = true, registry_enabled = true;
    bool watch_run_keys = true, watch_services = true, log_all_events = true, capture_command_line = true;
    int network_poll_ms = 1000, correlation_window_seconds = 120, context_retention_seconds = 300;
    std::size_t queue_capacity = 10000, max_history_events = 4096;
    std::string alert_min_severity = "medium", log_directory = "out";
    bool file_monitor_enabled = false, file_recursive = true, hash_enabled = true, signature_enabled = true;
    std::vector<std::string> file_roots;
    int max_watches = 64, scanner_workers = 2, scanner_timeout_seconds = 30, yara_cpu_percent = 20;
    std::size_t scanner_queue = 500;
    std::uint64_t max_file_bytes = 100ULL * 1024 * 1024;
    bool inventory_enabled = false, watch_tasks = true, watch_startup = true, watch_scm = true;
    int inventory_poll_seconds = 30;
    bool eventlog_enabled = false, sysmon_auto_detect = true, security_events_enabled = false,
         retain_raw_xml = false;
    std::vector<std::string> eventlog_channels = {"Microsoft-Windows-Sysmon/Operational", "System"};
    bool yara_enabled = false, threat_intel_enabled = false, remote_enabled = false;
    std::string yara_rule_dir = "rules/yara";
    bool storage_enabled = true;
    std::uint64_t storage_max_bytes = 2ULL * 1024 * 1024 * 1024;
    int event_retention_days = 14, incident_retention_days = 90;
    std::string pipe_name = "IRForge.Agent.v1";
    Json platform = Json::object();
    static Config load(const std::string &);
    Json json() const;
};
} // namespace irforge
