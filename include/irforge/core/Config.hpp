#pragma once
#include "Event.hpp"
namespace irforge {
struct Config {
    bool process_etw_enabled = true, network_enabled = true, registry_enabled = true;
    bool watch_run_keys = true, watch_services = true, log_all_events = true, capture_command_line = true;
    int network_poll_ms = 1000, correlation_window_seconds = 120, context_retention_seconds = 300;
    std::size_t queue_capacity = 10000, max_history_events = 4096;
    std::string alert_min_severity = "medium", log_directory = "out";
    static Config load(const std::string &);
    Json json() const;
};
} // namespace irforge
