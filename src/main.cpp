#include "irforge/cli/Commands.hpp"
#include "irforge/core/Config.hpp"
#include "irforge/core/EventBus.hpp"
#include "irforge/detection/BaselineEngine.hpp"
#include "irforge/enrichment/ArtifactEnricher.hpp"
#include "irforge/ipc/PipeServer.hpp"
#include "irforge/monitoring/FileMonitor.hpp"
#include "irforge/monitoring/IMonitor.hpp"
#include "irforge/monitoring/InventoryMonitor.hpp"
#include "irforge/remote/TlsTransport.hpp"
#include "irforge/replay/ReplayEngine.hpp"
#include "irforge/service/WindowsService.hpp"
#include "irforge/storage/SqliteStore.hpp"
#include "irforge/ti/TiEnricher.hpp"
#include "irforge/windows/EventLogSubscriber.hpp"
#include <QCoreApplication>
#include <QProcess>
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
const char *help = R"(IRForge 1.0.0-dev -- Windows Endpoint Evidence & Triage
Usage:
  irforge --help | version
  irforge rules validate --dir rules
  irforge replay --events FILE --rules rules --output NEW_DIRECTORY [--config FILE]
  irforge monitor [--config FILE] [--rules rules] [--output NEW_DIRECTORY]
                  [--duration-seconds N] [--allow-degraded] [--quiet] [--verbose]
  irforge agent status | health [--pipe NAME] [--json]
  irforge agent serve --db FILE [--pipe NAME] [--rules DIR]
  irforge agent query --table events|incidents|hosts [--pipe NAME] [--search TEXT]
  irforge storage inspect|maintain --db FILE [--confirm]
  irforge snapshot --output NEW_DIRECTORY [--include-evtx]
  irforge evidence verify --manifest FILE
  irforge rules list|test|import-sigma --help
  irforge yara validate --rules DIR | scan --rules DIR --path FILE
  irforge baseline show|learn|freeze|reset|import|export|compare --db FILE --host ID
  irforge baseline learn --pipe NAME --host ID --duration 3600 --opt-in
  irforge baseline compare --db FILE --host ID --window 24h
  irforge report --db FILE --incident ID --format html|pdf|json|csv|stix --output NEW_DIRECTORY
  irforge export events|incidents --db FILE --format json|csv --output NEW_DIRECTORY
  irforge cases create|list|export --db FILE --help
  irforge ti lookup|ioc-import|ioc-match|credential-set|credential-remove --help
  irforge service install|start|stop|status|uninstall --help
  irforge remote configure|enroll|send|query|status|disconnect --help
  irforge diagnostics --output NEW_DIRECTORY [--pipe NAME]
Details and option bounds: docs/operations.md. All commands accept --help.
Live ETW normally requires an elevated Windows 10/11 x64 terminal.
Read-only collectors; local logs may contain sensitive command lines and Registry data.
TCP polling can miss short-lived sockets. Registry writer PID is unknown.
)";
int run(int argc, char **argv) {
    stopRequested = false;
    std::vector<std::string> extendedArguments;
    for (int i = 0; i < argc; ++i)
        extendedArguments.emplace_back(argv[i]);
    if (std::find(extendedArguments.begin(), extendedArguments.end(), "--help") != extendedArguments.end()) {
        std::cout << help;
        return 0;
    }
    if (extendedArguments.size() > 1 && extendedArguments[1] == "report") {
        Arguments report(extendedArguments, 2,
                         {"--db", "--incident", "--format", "--output", "--out", "--pipe"});
        auto format = report.get("--format", "html");
        auto output = report.get("--output", report.get("--out"));
        if (output.empty())
            throw std::runtime_error("report requires --output NEW_DIRECTORY");
        if (format == "pdf") {
            std::unique_ptr<StoreWorker> store;
            std::unique_ptr<OperationGateway> gateway;
            std::unique_ptr<PipeServer> server;
            auto pipe = report.get("--pipe");
            if (pipe.empty()) {
                store = std::make_unique<StoreWorker>(report.require("--db"));
                auto rules =
                    filesystemPath(QCoreApplication::applicationDirPath().toStdString()) / "rules/internal";
                if (!std::filesystem::exists(rules))
                    rules = filesystemPath("rules/internal");
                gateway = std::make_unique<OperationGateway>(*store, rules.string());
                pipe = "IRForge.Report." + newUuid();
                server = std::make_unique<PipeServer>(pipe, *gateway);
                server->start();
            }
            QProcess process;
            process.start(QCoreApplication::applicationDirPath() + "/irforge_gui.exe",
                          {"--export-pdf", "--pipe", QString::fromStdString(pipe), "--incident",
                           QString::fromStdString(report.require("--incident")), "--output",
                           QString::fromStdString(output), "--error-log",
                           QString::fromStdString(output + ".error.txt")});
            if (!process.waitForStarted(5000) || !process.waitForFinished(60000)) {
                process.kill();
                process.waitForFinished(5000);
                throw std::runtime_error("PDF renderer deadline/start failure");
            }
            if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
                throw std::runtime_error("PDF renderer failed; inspect output.error.txt");
            std::cout << "PDF evidence and manifest: " << output << '\n';
            return 0;
        }
        extendedArguments = {extendedArguments[0],
                             "export",
                             "--db",
                             report.require("--db"),
                             "--incident",
                             report.require("--incident"),
                             "--format",
                             format,
                             "--output",
                             output};
    }
    if (auto handled = remoteCommand(extendedArguments))
        return *handled;
    if (auto handled = serviceCommand(extendedArguments,
                                      [](const std::vector<std::string> &arguments, std::stop_token token) {
                                          auto owned = arguments;
                                          std::vector<char *> pointers;
                                          for (auto &arg : owned)
                                              pointers.push_back(arg.data());
                                          std::jthread cancellation([token](std::stop_token stop) {
                                              while (!stop.stop_requested() && !token.stop_requested())
                                                  std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                              if (token.stop_requested())
                                                  stopRequested = true;
                                          });
                                          return run(static_cast<int>(pointers.size()), pointers.data());
                                      }))
        return *handled;
    if (auto handled = platformCommand(extendedArguments))
        return *handled;
    if (argc < 2 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "help") {
        std::cout << help;
        return 0;
    }
    std::string command = argv[1];
    if (command == "version") {
        if (argc != 2)
            throw std::runtime_error("version takes no options");
        std::cout << "IRForge 1.0.0-dev (v0.1 CLI compatible)\n";
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
    const std::set<std::string> values = {"--config",           "--rules", "--output", "--events", "--dir",
                                          "--duration-seconds", "--db",    "--pipe"};
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
            ? std::set<std::string>{"--config", "--rules", "--output", "--events", "--quiet", "--db"}
            : std::set<std::string>{"--config",           "--rules", "--output",
                                    "--duration-seconds", "--quiet", "--verbose",
                                    "--allow-degraded",   "--db",    "--pipe"};
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
    std::string replayHost = "replay", replaySession = "replay";
    if (command == "replay") {
        auto input = readReplay(options.at("--events"));
        if (!input.empty() && input.front().schemaVersion == 2) {
            replayHost = input.front().hostId;
            replaySession = input.front().sessionId;
            for (const auto &e : input)
                if (e.schemaVersion != 2 || e.hostId != replayHost || e.sessionId != replaySession)
                    throw std::runtime_error("replay requires one host/session per input; split fleet "
                                             "acquisitions before analysis");
        }
    }
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
                     {"version", "1.0.0-dev"},
                     {"host", host},
                     {"mode", command},
                     {"start_utc", formatUtc(start)},
                     {"stop_utc", nullptr},
                     {"configuration", config.json()},
                     {"result", "starting"}};
    const auto hostId = command == "replay" ? replayHost : stableHostId();
    const auto sessionId = command == "replay" ? replaySession : newUuid();
    metadata["host_id"] = hostId;
    metadata["session_id"] = sessionId;
    StoreWorker store(get("--db", config.log_directory + "/irforge.sqlite"), config.queue_capacity,
                      config.storage_max_bytes);
    std::unique_ptr<RemoteSender> remoteSender;
    if (command == "monitor" && config.remote_enabled) {
        auto connection = readJsonFile(config.platform.at("remote").at("config_path").get<std::string>());
        auto enrollment = store.call({{"op", "get"}, {"table", "settings"}, {"key", "remote/config"}});
        if (enrollment.is_null() || !enrollment.value("enabled", false))
            throw std::runtime_error(
                "explicit remote configure enrollment is required before enabling sender");
        remoteSender = std::make_unique<RemoteSender>(store, connection);
    }
    std::unique_ptr<OperationGateway> gateway;
    std::unique_ptr<PipeServer> pipeServer;
    if (command == "monitor" &&
        (options.contains("--pipe") || config.platform.value("ui", Json::object()).value("enabled", false))) {
        gateway =
            std::make_unique<OperationGateway>(store, get("--rules", "rules"), get("--config", ""), hostId);
        correlator.setRules(gateway->ruleSnapshot());
        auto readers = config.platform.value("ipc", Json::object())
                           .value("allowed_reader_sids", std::vector<std::string>{});
        pipeServer = std::make_unique<PipeServer>(get("--pipe", config.pipe_name), *gateway, readers);
        pipeServer->start();
    }
    std::unique_ptr<BaselineEngine> baseline;
    if (config.platform.value("baseline", Json::object()).value("enabled", false))
        baseline = std::make_unique<BaselineEngine>(store, hostId,
                                                    config.platform["baseline"].value("minimum_samples", 20));
    store.call({{"op", "session"}, {"host", hostId}, {"id", sessionId}, {"data", metadata}});
    store.call(
        {{"op", "put"}, {"table", "settings"}, {"key", "agent/effective-config"}, {"data", config.json()}});
    auto persistEvent = [&](const SecurityEvent &e) {
        store.enqueue({{"op", "event"}, {"data", upgradeEvent(Json(e), hostId, sessionId)}});
    };
    auto persistIncidents = [&](const std::vector<Incident> &updates) {
        for (const auto &i : updates)
            store.enqueue({{"op", "incident"}, {"data", incidentV2(i, hostId, sessionId)}});
    };
    writer.document("session-metadata.json", metadata);
    if (command == "replay") {
        replay(options.at("--events"), correlator, alerts, writer, metrics, config.log_all_events,
               ReplayCallbacks{persistEvent, persistIncidents});
        metadata["start_utc"] = formatUtc(metrics.start);
        metadata["stop_utc"] = nullptr;
        metadata["result"] = "complete";
        metadata["host"] = "offline";
        metadata["replay_input"] = options.at("--events");
        writer.document("session-metadata.json", metadata);
        store.call({{"op", "session"}, {"host", hostId}, {"id", sessionId}, {"data", metadata}});
        store.flush();
        if (store.failures() || store.dropped())
            throw std::runtime_error("replay persistence incomplete; inspect storage diagnostics");
        std::cout << "Replay complete: " << alerts.count() << " alerts in " << config.log_directory << '\n';
        return 0;
    }
#ifndef _WIN32
    throw std::runtime_error("live monitoring requires Windows; replay and rules validation are portable");
#else
    SetConsoleCtrlHandler(consoleHandler, TRUE);
    // A GUI-started monitor uses a per-session local event for graceful shutdown.
    wchar_t guiStopName[256]{};
    const auto guiStopLength = GetEnvironmentVariableW(L"IRFORGE_STOP_EVENT", guiStopName, 256);
    Handle guiStop(guiStopLength > 0 && guiStopLength < 256 ? OpenEventW(SYNCHRONIZE, FALSE, guiStopName)
                                                            : nullptr);
    EventBus bus(config.queue_capacity);
    std::unique_ptr<TiEnricher> tiEnricher;
    if (config.threat_intel_enabled ||
        !store.call({{"op", "get"}, {"table", "settings"}, {"key", "ti/local-ioc-feed"}}).is_null())
        tiEnricher = std::make_unique<TiEnricher>(store, bus, config);
    std::unique_ptr<ArtifactEnricher> enricher;
    if (config.file_monitor_enabled)
        enricher = std::make_unique<ArtifactEnricher>(bus, config);
    auto liveHealth = [&](Millis now) {
        auto state = metrics.json(now, bus.dropped(), correlator.incidents().size(), correlator.evicted());
        state["event_queue_depth"] = bus.depth();
        state["writer"] = store.stats();
        if (enricher)
            state["scanner"] = enricher->health();
        if (tiEnricher)
            state["threat_intelligence"] = tiEnricher->health();
        std::uint64_t count = 0;
        for (const auto &[source, total] : metrics.received) {
            (void)source;
            count += total;
        }
        state["events_per_second_since_start"] = count * 1000.0 / std::max<Millis>(1, now - metrics.start);
        return state;
    };
    std::vector<std::unique_ptr<IMonitor>> monitors;
    std::vector<std::string> monitorNames;
    for (const auto &[name, enabled] :
         std::vector<std::pair<std::string, bool>>{{"process_etw", config.process_etw_enabled},
                                                   {"network", config.network_enabled},
                                                   {"registry", config.registry_enabled},
                                                   {"filesystem_diff", config.file_monitor_enabled},
                                                   {"inventory", config.inventory_enabled},
                                                   {"windows_eventlog", config.eventlog_enabled}})
        if (name != "windows_eventlog" || !enabled)
            metrics.sources[name] = StatusPayload{enabled ? "starting" : "disabled",
                                                  enabled ? "initializing" : "Disabled by configuration",
                                                  0,
                                                  0,
                                                  0,
                                                  0};
    for (const auto &[name, enabled] :
         std::vector<std::pair<std::string, bool>>{{"process_etw", config.process_etw_enabled},
                                                   {"network", config.network_enabled},
                                                   {"registry", config.registry_enabled},
                                                   {"filesystem_diff", config.file_monitor_enabled},
                                                   {"inventory", config.inventory_enabled},
                                                   {"windows_eventlog", config.eventlog_enabled}})
        if (enabled)
            monitorNames.push_back(name);
    writer.document("monitor-health.json", metrics.json(utcNow(), 0, 0, 0));
    if (config.process_etw_enabled)
        monitors.push_back(std::make_unique<ProcessMonitor>(bus, config));
    if (config.network_enabled)
        monitors.push_back(std::make_unique<NetworkMonitor>(bus, config));
    if (config.registry_enabled)
        monitors.push_back(std::make_unique<RegistryMonitor>(bus, config));
    if (config.file_monitor_enabled)
        monitors.push_back(std::make_unique<FileMonitor>(bus, config));
    if (config.inventory_enabled)
        monitors.push_back(std::make_unique<InventoryMonitor>(bus, config));
    if (config.eventlog_enabled)
        monitors.push_back(std::make_unique<EventLogMonitor>(bus, config, store));
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
            Millis nextHealth = 0, nextRetention = 0;
            std::uint64_t oldDrops = 0;
            for (;;) {
                auto item = bus.popFor(std::chrono::seconds(1));
                if (utcNow() >= nextRetention) {
                    auto retention = store.call({{"op", "retention"},
                                                 {"event_days", config.event_retention_days},
                                                 {"incident_days", config.incident_retention_days}});
                    store.enqueue(
                        {{"op", "put"}, {"table", "health"}, {"key", "retention"}, {"data", retention}});
                    nextRetention = utcNow() + 3600000;
                }
                if (gateway && gateway->consumeRuleChanges())
                    correlator.setRules(gateway->ruleSnapshot());
                if (gateway && gateway->consumeBaselineChanges()) {
                    if (baseline)
                        baseline->flush();
                    else
                        baseline = std::make_unique<BaselineEngine>(
                            store, hostId,
                            config.platform.value("baseline", Json::object()).value("minimum_samples", 20));
                }
                if (!item) {
                    if (bus.drained())
                        break;
                    auto now = utcNow();
                    auto updates = correlator.expire(now);
                    persistIncidents(updates);
                    alerts.update(updates, now);
                    if (now >= nextHealth) {
                        if (baseline)
                            baseline->flush();
                        writer.flush();
                        writer.document("monitor-health.json", liveHealth(now));
                        store.enqueue({{"op", "put"},
                                       {"table", "health"},
                                       {"key", "collection"},
                                       {"data", liveHealth(now)}});
                        store.enqueue({{"op", "flush"}});
                        nextHealth = now + 5000;
                    }
                    continue;
                }
                auto &e = *item;
                e.id = ++sequence;
                e.host = host;
                if (e.schemaVersion == 2 ||
                    static_cast<int>(e.type) > static_cast<int>(EventType::MonitorStatus)) {
                    e.hostId = hostId;
                    e.sessionId = sessionId;
                    e.uniqueId = hostId + "/" + sessionId + "/" + std::to_string(e.id);
                    e.observedAtUtc = utcNow();
                }
                enrichProcess(e);
                if (enricher)
                    enricher->consider(e);
                if (tiEnricher)
                    tiEnricher->consider(e);
                metrics.observe(e);
                persistEvent(e);
                if (baseline)
                    for (auto &deviation : baseline->observe(e))
                        bus.publish(std::move(deviation));
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
                auto updates = correlator.ingest(e);
                persistIncidents(updates);
                alerts.update(updates, utcNow());
                auto drops = bus.dropped();
                if (drops != oldDrops) {
                    std::cerr << "DEGRADED event queue overflow: " << drops << " dropped events\n";
                    oldDrops = drops;
                }
                if (utcNow() >= nextHealth) {
                    if (baseline)
                        baseline->flush();
                    writer.flush();
                    writer.document("monitor-health.json", liveHealth(utcNow()));
                    store.enqueue({{"op", "put"},
                                   {"table", "health"},
                                   {"key", "collection"},
                                   {"data", liveHealth(utcNow())}});
                    store.enqueue({{"op", "flush"}});
                    nextHealth = utcNow() + 5000;
                }
            }
            writer.flush();
            if (baseline)
                baseline->flush();
            writer.document("monitor-health.json", liveHealth(utcNow()));
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
            std::string source = monitorNames.at(index);
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
    while (!stopRequested && (duration == 0 || std::chrono::steady_clock::now() < deadline) &&
           (!guiStop.value || WaitForSingleObject(guiStop.value, 0) != WAIT_OBJECT_0))
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    for (auto &monitor : monitors)
        monitor->stop();
    if (tiEnricher)
        tiEnricher->stop();
    if (enricher)
        enricher->stop();
    bus.close();
    dispatcher.join();
    SetConsoleCtrlHandler(consoleHandler, FALSE);
    metadata["stop_utc"] = formatUtc(utcNow());
    metadata["result"] = failed ? "failed" : startupFailed ? "degraded" : "complete";
    store.enqueue(
        {{"op", "put"}, {"table", "health"}, {"key", "collection"}, {"data", liveHealth(utcNow())}});
    if (pipeServer)
        pipeServer->stop();
    metadata["queue_drops"] = bus.dropped();
    metadata["storage_queue_drops"] = store.dropped();
    metadata["storage_failures"] = store.failures();
    writer.document("session-metadata.json", metadata);
    store.call({{"op", "session"}, {"host", hostId}, {"id", sessionId}, {"data", metadata}});
    store.flush();
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
        int qtArgc = argc;
        QCoreApplication application(qtArgc, argv.data());
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
