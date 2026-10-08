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
                                        "log_directory"};
    if (!j.is_object() || j.value("schema_version", 0) != 1)
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
    return {{"schema_version", 1},
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
}
} // namespace irforge
