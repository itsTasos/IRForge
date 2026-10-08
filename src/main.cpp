#include "irforge/core/Config.hpp"
#include "irforge/core/EventBus.hpp"
#include "irforge/monitoring/IMonitor.hpp"
#include "irforge/replay/ReplayEngine.hpp"
#include <atomic>
#include <csignal>
#include <iostream>
#include <map>
#include <set>
#include <thread>
#ifdef _WIN32
#include "irforge/monitoring/Win32.hpp"
#endif
namespace {
using namespace irforge;
std::atomic<bool> stopRequested = false;
#ifdef _WIN32
BOOL WINAPI consoleHandler(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT) {
        stopRequested = true;
        return TRUE;
    }
    return FALSE;
}
#else
void signalHandler(int) { stopRequested = true; }
#endif
const char *help = R"(IRForge 0.1.0 -- Lightweight Windows Endpoint Detection & Triage
Usage:
  irforge --help | version
  irforge rules validate --dir rules
  irforge replay --events FILE --rules rules --output NEW_DIRECTORY [--config FILE]
  irforge monitor [--config FILE] [--rules rules] [--output NEW_DIRECTORY]
                  [--duration-seconds N] [--allow-degraded] [--quiet] [--verbose]
Live ETW normally requires an elevated Windows 10/11 x64 terminal.
Read-only collectors; local logs may contain sensitive command lines and Registry data.
TCP polling can miss short-lived sockets. Registry writer PID is unknown.
)";
int run(int argc, char **argv) {
    if (argc < 2 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "help") {
        std::cout << help;
        return 0;
    }
    std::string command = argv[1];
    if (command == "version") {
        if (argc != 2)
            throw std::runtime_error("version takes no options");
        std::cout << "IRForge 0.1.0\n";
        return 0;
    }
    int first = 2;
    if (command == "rules") {
        if (argc < 3 || std::string(argv[2]) != "validate")
            throw std::runtime_error("expected rules validate");
        first = 3;
    } else if (command != "monitor" && command != "replay")
        throw std::runtime_error("unknown command: " + command);
    std::map<std::string, std::string> options;
    const std::set<std::string> flags = {"--allow-degraded", "--quiet", "--verbose"};
    const std::set<std::string> values = {"--config", "--rules", "--output",
                                          "--events", "--dir",   "--duration-seconds"};
    for (int i = first; i < argc; ++i) {
        std::string key = argv[i];
        if (options.contains(key))
            throw std::runtime_error("duplicate option: " + key);
        if (flags.contains(key))
            options[key] = "true";
        else if (values.contains(key) && i + 1 < argc)
            options[key] = argv[++i];
        else
            throw std::runtime_error("unknown option or missing value: " + key);
    }
    auto get = [&](const std::string &key, const std::string &fallback) {
        return options.contains(key) ? options.at(key) : fallback;
    };
    const std::set<std::string> allowed =
        command == "rules" ? std::set<std::string>{"--dir"}
        : command == "replay"
            ? std::set<std::string>{"--config", "--rules", "--output", "--events", "--quiet"}
            : std::set<std::string>{"--config", "--rules",   "--output",        "--duration-seconds",
                                    "--quiet",  "--verbose", "--allow-degraded"};
    for (const auto &[key, value] : options) {
        (void)value;
        if (!allowed.contains(key))
            throw std::runtime_error("option is not supported by " + command + ": " + key);
    }
    if (command == "rules") {
        auto rules = RuleEngine::load(get("--dir", "rules"));
        std::cout << "Validated " << rules.rules().size() << " rules\n";
        return 0;
    }
    Config config = options.contains("--config") ? Config::load(options.at("--config")) : Config{};
    config.log_directory = get("--output", config.log_directory);
    auto rules = RuleEngine::load(get("--rules", "rules"));
    if (command == "replay" && !options.contains("--events"))
        throw std::runtime_error("replay requires --events");
    if (command == "replay")
        (void)readReplay(options.at("--events")); // Validate before creating output.
    int duration = 0;
    if (options.contains("--duration-seconds")) {
        std::size_t consumed = 0;
        duration = std::stoi(options.at("--duration-seconds"), &consumed);
        if (consumed != options.at("--duration-seconds").size() || duration < 1 || duration > 86400)
            throw std::runtime_error("duration must be 1..86400 seconds");
    }
    JsonlWriter writer(config.log_directory);
    Correlator correlator(std::move(rules), config);
    AlertManager alerts(writer, config.alert_min_severity, options.contains("--quiet"));
    Metrics metrics;
    metrics.start = utcNow();
    std::string host = "offline";
#ifdef _WIN32
    wchar_t computer[256]{};
    DWORD computerSize = 256;
    if (GetComputerNameW(computer, &computerSize))
        host = utf8(std::wstring(computer, computerSize));
#endif
    auto start = metrics.start;
    Json metadata = {{"schema_version", 1},
                     {"version", "0.1.0"},
                     {"host", host},
                     {"mode", command},
                     {"start_utc", formatUtc(start)},
                     {"stop_utc", nullptr},
                     {"configuration", config.json()},
                     {"result", "starting"}};
    writer.document("session-metadata.json", metadata);
    if (command == "replay") {
        replay(options.at("--events"), correlator, alerts, writer, metrics, config.log_all_events);
        metadata["start_utc"] = formatUtc(metrics.start);
        metadata["stop_utc"] = nullptr;
        metadata["result"] = "complete";
        metadata["host"] = "offline";
        metadata["replay_input"] = options.at("--events");
        writer.document("session-metadata.json", metadata);
        std::cout << "Replay complete: " << alerts.count() << " alerts in " << config.log_directory << '\n';
        return 0;
    }
#ifndef _WIN32
    throw std::runtime_error("live monitoring requires Windows; replay and rules validation are portable");
#else
    SetConsoleCtrlHandler(consoleHandler, TRUE);
    EventBus bus(config.queue_capacity);
    std::vector<std::unique_ptr<IMonitor>> monitors;
    for (const auto &[name, enabled] :
         std::vector<std::pair<std::string, bool>>{{"process_etw", config.process_etw_enabled},
                                                   {"network", config.network_enabled},
                                                   {"registry", config.registry_enabled}})
        metrics.sources[name] = StatusPayload{enabled ? "starting" : "disabled",
                                              enabled ? "initializing" : "Disabled by configuration",
                                              0,
                                              0,
                                              0,
                                              0};
    writer.document("monitor-health.json", metrics.json(utcNow(), 0, 0, 0));
    if (config.process_etw_enabled)
        monitors.push_back(std::make_unique<ProcessMonitor>(bus, config));
    if (config.network_enabled)
        monitors.push_back(std::make_unique<NetworkMonitor>(bus, config));
    if (config.registry_enabled)
        monitors.push_back(std::make_unique<RegistryMonitor>(bus, config));
    std::cout << "Sources: ETW=" << config.process_etw_enabled << " TCP4/6=" << config.network_enabled
              << " Registry=" << config.registry_enabled << ". Local sensitive logs: " << config.log_directory
              << "\n";
    if (!config.capture_command_line)
        std::cerr
            << "DEGRADED detection: command-line capture disabled; encoded-command rules cannot match.\n";
    if (!config.process_etw_enabled || !config.network_enabled || !config.registry_enabled)
        std::cerr << "DEGRADED coverage: one or more telemetry sources disabled by configuration.\n";
    std::exception_ptr dispatchError;
    std::atomic<bool> failed = false;
    std::jthread dispatcher([&] {
        try {
            EventId sequence = 0;
            Millis nextHealth = 0;
            std::uint64_t oldDrops = 0;
            for (;;) {
                auto item = bus.popFor(std::chrono::seconds(1));
                if (!item) {
                    if (bus.drained())
                        break;
                    auto now = utcNow();
                    alerts.update(correlator.expire(now), now);
                    if (now >= nextHealth) {
                        writer.flush();
                        writer.document("monitor-health.json",
                                        metrics.json(now, bus.dropped(), correlator.incidents().size(),
                                                     correlator.evicted()));
                        nextHealth = now + 5000;
                    }
                    continue;
                }
                auto &e = *item;
                e.id = ++sequence;
                e.host = host;
                enrichProcess(e);
                metrics.observe(e);
                if (config.log_all_events)
                    writer.event(e);
                if (auto s = std::get_if<StatusPayload>(&e.payload)) {
                    if (options.contains("--verbose") && s->state != "degraded")
                        std::cout << e.source << " " << s->state << ": " << s->message << '\n';
                    if (s->state == "degraded") {
                        std::cerr << "DEGRADED " << e.source << ": " << s->message << '\n';
                        if (!options.contains("--allow-degraded")) {
                            failed = true;
                            stopRequested = true;
                        }
                    }
                } else if (!options.contains("--quiet")) {
                    std::cout << formatUtc(e.timestampUtc) << ' ' << e.source << ' ' << eventTypeName(e.type);
                    if (auto p = std::get_if<ProcessPayload>(&e.payload))
                        std::cout << " pid=" << p->identity.pid << " " << p->imagePath.value_or("unknown");
                    if (auto n = std::get_if<TcpPayload>(&e.payload))
                        std::cout << " pid=" << n->ownerPid << " " << n->remoteAddress << ':' << n->remotePort
                                  << " " << n->state << (n->firstSnapshot ? " baseline" : "");
                    if (auto r = std::get_if<RegistryPayload>(&e.payload))
                        std::cout << ' ' << r->hive << '\\' << r->keyPath << " value=" << r->valueName
                                  << " writer=unknown";
                    std::cout << '\n';
                }
                alerts.update(correlator.ingest(e), utcNow());
                auto drops = bus.dropped();
                if (drops != oldDrops) {
                    std::cerr << "DEGRADED event queue overflow: " << drops << " dropped events\n";
                    oldDrops = drops;
                }
                if (utcNow() >= nextHealth) {
                    writer.flush();
                    writer.document(
                        "monitor-health.json",
                        metrics.json(utcNow(), drops, correlator.incidents().size(), correlator.evicted()));
                    nextHealth = utcNow() + 5000;
                }
            }
            writer.flush();
            writer.document(
                "monitor-health.json",
                metrics.json(utcNow(), bus.dropped(), correlator.incidents().size(), correlator.evicted()));
        } catch (...) {
            dispatchError = std::current_exception();
            failed = true;
            stopRequested = true;
        }
    });
    bool startupFailed = false;
    std::size_t index = 0;
    for (auto &monitor : monitors) {
        try {
            monitor->start();
        } catch (const std::exception &ex) {
            monitor->stop();
            startupFailed = true;
            std::string source = config.process_etw_enabled && index == 0 ? "process_etw"
                                 : config.network_enabled && index == (config.process_etw_enabled ? 1u : 0u)
                                     ? "network"
                                     : "registry";
            auto win = dynamic_cast<const WindowsError *>(&ex);
            monitorStatus(bus, source, "degraded", ex.what(), win ? win->code : 0);
            if (!options.contains("--allow-degraded")) {
                failed = true;
                stopRequested = true;
                break;
            }
        }
        ++index;
    }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(duration);
    while (!stopRequested && (duration == 0 || std::chrono::steady_clock::now() < deadline))
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    for (auto &monitor : monitors)
        monitor->stop();
    bus.close();
    dispatcher.join();
    SetConsoleCtrlHandler(consoleHandler, FALSE);
    metadata["stop_utc"] = formatUtc(utcNow());
    metadata["result"] = failed ? "failed" : startupFailed ? "degraded" : "complete";
    metadata["queue_drops"] = bus.dropped();
    writer.document("session-metadata.json", metadata);
    writer.flush();
    if (dispatchError)
        std::rethrow_exception(dispatchError);
    return failed ? 2 : 0;
#endif
}
} // namespace
#ifdef _WIN32
int wmain(int argc, wchar_t **wideArgv) {
    try {
        std::vector<std::string> arguments;
        arguments.reserve(static_cast<std::size_t>(argc));
        for (int i = 0; i < argc; ++i)
            arguments.push_back(irforge::utf8(wideArgv[i]));
        std::vector<char *> argv;
        for (auto &argument : arguments)
            argv.push_back(argument.data());
        return run(argc, argv.data());
    } catch (const std::exception &ex) {
        std::cerr << "IRForge error: " << ex.what() << '\n';
        return 1;
    }
}
#else
int main(int argc, char **argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception &ex) {
        std::cerr << "IRForge error: " << ex.what() << '\n';
        return 1;
    }
}
#endif
