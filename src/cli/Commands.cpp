#include "irforge/cli/Commands.hpp"
#include "irforge/core/Schema.hpp"
#include "irforge/detection/AttackMapper.hpp"
#include "irforge/detection/BaselineEngine.hpp"
#include "irforge/detection/SigmaImporter.hpp"
#include "irforge/detection/YaraScanner.hpp"
#include "irforge/enrichment/HashEngine.hpp"
#include "irforge/ipc/PipeServer.hpp"
#include "irforge/monitoring/Win32.hpp"
#include "irforge/replay/ReplayEngine.hpp"
#include "irforge/reporting/Evidence.hpp"
#include "irforge/reporting/ReportExporter.hpp"
#include "irforge/ti/VirusTotal.hpp"
#include "irforge/windows/EventLogSubscriber.hpp"
#include <charconv>
#include <fstream>
#include <iostream>
namespace irforge {
Arguments::Arguments(const std::vector<std::string> &args, std::size_t first,
                     const std::set<std::string> &values, const std::set<std::string> &flags) {
    for (std::size_t i = first; i < args.size(); ++i) {
        const auto &key = args[i];
        if (values_.contains(key))
            throw std::runtime_error("duplicate option: " + key);
        if (flags.contains(key))
            values_[key] = "true";
        else if (values.contains(key) && i + 1 < args.size() && !args[i + 1].starts_with("--"))
            values_[key] = args[++i];
        else
            throw std::runtime_error("unknown option or missing value: " + key);
    }
}
std::string Arguments::get(const std::string &key, const std::string &fallback) const {
    auto it = values_.find(key);
    return it == values_.end() ? fallback : it->second;
}
std::string Arguments::require(const std::string &key) const {
    auto value = get(key);
    if (value.empty())
        throw std::runtime_error("required option: " + key);
    return value;
}
int Arguments::integer(const std::string &key, int fallback, int minimum, int maximum) const {
    if (!has(key))
        return fallback;
    auto value = get(key);
    int result = 0;
    auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || result < minimum ||
        result > maximum)
        throw std::runtime_error(key + " outside supported range");
    return result;
}
std::optional<int> platformCommand(const std::vector<std::string> &args) {
    if (args.size() < 2)
        return {};
    if (args[1] == "diagnostics") {
        Arguments options(args, 2, {"--output", "--pipe"});
        auto output = options.require("--output");
        privateDirectory(output, true);
        auto base = filesystemPath(output);
        Json document = {{"schema_version", 1},
                         {"generated_at", formatUtc(utcNow())},
                         {"application", "IRForge 1.0.0-dev"},
                         {"private_documents_copied", false}};
        try {
            document["agent"] = pipeRequest(options.get("--pipe", "IRForge.Agent.v1"), {{"op", "health"}});
        } catch (const std::exception &e) {
            document["agent"] = {{"state", "unavailable"}, {"reason", e.what()}};
        }
        writeDocument(base / "diagnostics.json", document);
        writeDocument(base / "manifest.json", evidenceManifest(output, "diagnostics"));
        zipEvidence(output, output + ".zip");
        std::cout << output << ".zip\n";
        return 0;
    }
    if (args[1] == "storage" && args.size() > 2) {
        Arguments options(args, 3, {"--db", "--event-days", "--incident-days"}, {"--confirm"});
        StoreWorker store(options.require("--db"));
        if (args[2] == "inspect") {
            std::cout << store.call({{"op", "health"}}).dump(2) << '\n';
            return 0;
        }
        if (args[2] == "maintain") {
            if (!options.has("--confirm"))
                throw std::runtime_error("retention requires --confirm; exported evidence is preserved");
            auto result = store.call({{"op", "retention"},
                                      {"event_days", options.integer("--event-days", 14, 1, 3650)},
                                      {"incident_days", options.integer("--incident-days", 90, 1, 3650)}});
            store.flush();
            std::cout << result.dump(2) << '\n';
            return 0;
        }
        throw std::runtime_error("expected storage inspect/maintain");
    }
    if (args[1] == "ti" && args.size() > 2) {
        Arguments options(args, 3, {"--db", "--kind", "--indicator", "--target", "--feed"},
                          {"--opt-in", "--key-stdin", "--confirm"});
        if (args[2] == "credential-set") {
            if (!options.has("--key-stdin") || !options.has("--confirm"))
                throw std::runtime_error(
                    "credential-set requires --key-stdin --confirm; never pass keys in arguments");
            std::string key;
            std::getline(std::cin, key);
            saveTiCredential(options.get("--target", "IRForge.VirusTotal.v1"), key);
            std::fill(key.begin(), key.end(), '\0');
            std::cout << "Credential stored for the current Windows account\n";
            return 0;
        }
        if (args[2] == "credential-remove") {
            if (!options.has("--confirm"))
                throw std::runtime_error("credential-remove requires --confirm");
            removeTiCredential(options.get("--target", "IRForge.VirusTotal.v1"));
            return 0;
        }
        if (args[2] == "lookup") {
            StoreWorker store(options.require("--db"));
            VirusTotalClient client(store);
            auto result =
                client.lookup(options.require("--kind"), options.require("--indicator"),
                              options.has("--opt-in"), options.get("--target", "IRForge.VirusTotal.v1"));
            std::cout << result.dump(2) << '\n';
            return result.value("status", std::string{}) == "complete" ||
                           result.value("status", std::string{}) == "not_found"
                       ? 0
                       : 2;
        }
        if (args[2] == "ioc-match") {
            auto path = filesystemPath(options.require("--feed"));
            Json feed;
            if (lower(path.extension().string()) == ".csv") {
                std::ifstream file(path, std::ios::binary);
                std::string bytes(1048577, '\0');
                file.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
                bytes.resize(static_cast<std::size_t>(file.gcount()));
                if (!file && !file.eof())
                    throw std::runtime_error("IOC CSV read failed");
                feed = parseIocCsv(bytes, options.get("--feed"));
            } else
                feed = readJsonFile(options.require("--feed"));
            IocMatcher matcher(feed);
            std::cout << matcher.match(options.require("--kind"), options.require("--indicator")).dump(2)
                      << '\n';
            return 0;
        }
        if (args[2] == "ioc-import") {
            if (!options.has("--confirm"))
                throw std::runtime_error("IOC import requires explicit reviewed-feed confirmation");
            auto path = filesystemPath(options.require("--feed"));
            Json feed;
            if (lower(path.extension().string()) == ".csv") {
                std::ifstream file(path, std::ios::binary);
                std::string bytes(1048577, '\0');
                file.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
                bytes.resize(static_cast<std::size_t>(file.gcount()));
                if (!file && !file.eof())
                    throw std::runtime_error("IOC CSV read failed");
                feed = parseIocCsv(bytes, options.get("--feed"));
            } else
                feed = readJsonFile(options.require("--feed"));
            IocMatcher matcher(feed);
            StoreWorker store(options.require("--db"));
            store.call({{"op", "put"},
                        {"table", "settings"},
                        {"key", "ti/local-ioc-feed"},
                        {"data", matcher.feed()}});
            store.call({{"op", "audit"},
                        {"author", "local IOC operator"},
                        {"data", {{"operation", "ioc_import"}, {"source", matcher.feed()["source"]}}}});
            std::cout << "Reviewed local IOC feed imported\n";
            return 0;
        }
        throw std::runtime_error("expected ti lookup/credential-set/credential-remove/ioc-import/ioc-match");
    }
    if (args[1] == "cases" && args.size() > 2) {
        Arguments options(args, 3, {"--db", "--title", "--incidents", "--case", "--output"});
        StoreWorker store(options.require("--db"));
        if (args[2] == "list") {
            std::cout << store.call({{"op", "query"}, {"table", "cases"}, {"limit", 500}}).dump(2) << '\n';
            return 0;
        }
        if (args[2] == "export") {
            auto selection = store.call({{"op", "query"},
                                         {"table", "cases"},
                                         {"filters", {{"id", options.require("--case")}}},
                                         {"limit", 1}});
            if (selection["rows"].empty())
                throw std::runtime_error("case not found");
            auto document = selection["rows"][0];
            auto output = options.require("--output");
            privateDirectory(output, true);
            auto base = filesystemPath(output);
            writeDocument(base / "case.json", document);
            int index = 0;
            for (const auto &incident : document.at("incident_snapshots")) {
                std::ofstream html(base / ("incident-" + std::to_string(++index) + ".html"),
                                   std::ios::binary);
                html << incidentHtml(incident, {{"case_id", document.at("case_id")},
                                                {"archived_revision", incident.at("revision")}});
                if (!html)
                    throw std::runtime_error("case report write failed");
            }
            writeDocument(base / "manifest.json", evidenceManifest(output, document.at("case_id")));
            zipEvidence(output, output + ".zip");
            std::cout << output << ".zip\n";
            return 0;
        }
        if (args[2] == "create") {
            auto text = options.require("--incidents");
            std::vector<std::string> ids;
            std::size_t begin = 0;
            for (;;) {
                auto end = text.find(',', begin);
                ids.push_back(text.substr(begin, end - begin));
                if (end == std::string::npos)
                    break;
                begin = end + 1;
            }
            std::cout << store
                             .call({{"op", "case_create"},
                                    {"title", options.require("--title")},
                                    {"incident_ids", ids},
                                    {"author", "local CLI operator"}})
                             .dump(2)
                      << '\n';
            return 0;
        }
        throw std::runtime_error("expected cases create/list");
    }
    if (args[1] == "export") {
        if (args.size() > 2 && (args[2] == "events" || args[2] == "incidents")) {
            Arguments options(args, 3, {"--db", "--format", "--output", "--out", "--host", "--search"});
            auto output = options.get("--output", options.get("--out"));
            if (output.empty())
                throw std::runtime_error("export requires --output NEW_DIRECTORY");
            auto format = options.get("--format", "json");
            if (format != "json" && format != "csv")
                throw std::runtime_error("table export format must be json/csv");
            StoreWorker store(options.require("--db"));
            Json filters = Json::object();
            if (options.has("--host"))
                filters["host"] = options.get("--host");
            if (options.has("--search"))
                filters["search"] = options.get("--search");
            privateDirectory(output, true);
            auto base = filesystemPath(output);
            std::ofstream file(base / (args[2] + (format == "json" ? ".json" : ".csv")), std::ios::binary);
            if (format == "json")
                file << "[\n";
            else
                file << "identifier,document\r\n";
            bool first = true;
            std::size_t count = 0;
            for (int offset = 0;; offset += 100) {
                auto page = store.call({{"op", "query"},
                                        {"table", args[2]},
                                        {"filters", filters},
                                        {"limit", 100},
                                        {"offset", offset}});
                for (const auto &row : page["rows"]) {
                    if (++count > 100000)
                        throw std::runtime_error("export exceeds 100000 rows; narrow filters");
                    if (format == "json") {
                        if (!first)
                            file << ",\n";
                        file << row.dump();
                    } else
                        file << csvCell(row.value(args[2] == "events" ? "event_id" : "incident_id",
                                                  std::string{}))
                             << ',' << csvCell(row.dump()) << "\r\n";
                    first = false;
                }
                if (!page.at("has_more").get<bool>())
                    break;
            }
            if (format == "json")
                file << "\n]\n";
            file.close();
            if (!file)
                throw std::runtime_error("export write failed");
            writeDocument(base / "export-context.json", {{"schema_version", 1},
                                                         {"table", args[2]},
                                                         {"filters", filters},
                                                         {"rows", count},
                                                         {"exported_at", formatUtc(utcNow())}});
            writeDocument(base / "manifest.json", evidenceManifest(output, "table-export"));
            std::cout << output << '\n';
            return 0;
        }
        Arguments options(args, 2, {"--db", "--incident", "--output", "--format"});
        StoreWorker store(options.require("--db"));
        std::cout << exportIncident(store, options.require("--incident"), options.require("--output"),
                                    options.get("--format", "html"))
                         .dump(2)
                  << '\n';
        return 0;
    }
    if (args[1] == "agent" && args.size() > 2) {
        if (args[2] == "request") {
            Arguments options(args, 3, {"--pipe", "--request", "--sha256"}, {"--confirm"});
            if (!options.has("--confirm"))
                throw std::runtime_error("administrative request requires explicit --confirm");
            auto path = options.require("--request");
            auto expected = options.require("--sha256");
            std::ifstream input(filesystemPath(path), std::ios::binary);
            if (!input)
                throw std::runtime_error("administrative request unavailable");
            std::string wire(1048577, '\0');
            input.read(wire.data(), static_cast<std::streamsize>(wire.size()));
            wire.resize(static_cast<std::size_t>(input.gcount()));
            if (wire.size() > 1048576)
                throw std::runtime_error("administrative request too large");
            auto digest =
                sha256Bytes(std::span(reinterpret_cast<const std::uint8_t *>(wire.data()), wire.size()));
            auto bytes = Json::parse(wire);
            validateDocument(bytes);
            if (digest != expected)
                throw std::runtime_error("administrative request hash changed");
            const std::set<std::string> writes = {"annotate",        "rule_toggle",   "case_create",
                                                  "baseline_change", "configuration", "ti_lookup"};
            if (!writes.contains(bytes.at("op").get<std::string>()))
                throw std::runtime_error("operation not allowed by elevation broker");
            std::cout << pipeRequest(options.get("--pipe", "IRForge.Agent.v1"), bytes).dump(2) << '\n';
            return 0;
        }
        if (args[2] == "serve") {
            Arguments options(args, 3, {"--db", "--pipe", "--rules", "--duration-seconds"});
            auto db = options.require("--db");
            if (!std::filesystem::exists(filesystemPath(db)))
                throw std::runtime_error("agent serve requires an existing evidence database");
            StoreWorker store(db);
            OperationGateway gateway(store, options.get("--rules", "rules/internal"));
            PipeServer server(options.get("--pipe", "IRForge.Agent.v1"), gateway);
            server.start();
            int duration = options.integer("--duration-seconds", 3600, 1, 86400);
            std::cout << "Serving real stored evidence over authenticated local pipe for " << duration
                      << " seconds\n";
            auto end = std::chrono::steady_clock::now() + std::chrono::seconds(duration);
            wchar_t guiStopName[256]{};
            const auto guiStopLength = GetEnvironmentVariableW(L"IRFORGE_STOP_EVENT", guiStopName, 256);
            Handle guiStop(guiStopLength > 0 && guiStopLength < 256
                               ? OpenEventW(SYNCHRONIZE, FALSE, guiStopName)
                               : nullptr);
            while (std::chrono::steady_clock::now() < end &&
                   (!guiStop.value || WaitForSingleObject(guiStop.value, 0) != WAIT_OBJECT_0))
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            server.stop();
            return 0;
        }
        if (args[2] == "query") {
            Arguments options(args, 3, {"--pipe", "--table", "--search", "--limit", "--offset"});
            Json filters = Json::object();
            if (options.has("--search"))
                filters["search"] = options.get("--search");
            auto result = pipeRequest(options.get("--pipe", "IRForge.Agent.v1"),
                                      {{"op", "query"},
                                       {"table", options.get("--table", "incidents")},
                                       {"filters", filters},
                                       {"limit", options.integer("--limit", 50, 1, 500)},
                                       {"offset", options.integer("--offset", 0, 0, 10000000)}});
            std::cout << result.dump(2) << '\n';
            return 0;
        }
        if (args[2] == "health" || args[2] == "status") {
            Arguments options(args, 3, {"--pipe"}, {"--json"});
            std::cout << pipeRequest(options.get("--pipe", "IRForge.Agent.v1"), {{"op", "health"}}).dump(2)
                      << '\n';
            return 0;
        }
        throw std::runtime_error("expected agent serve/query/health");
    }
    if (args[1] == "baseline" && args.size() > 2) {
        Arguments options(args, 3,
                          {"--db", "--host", "--events", "--input", "--output", "--minimum-samples",
                           "--duration", "--window", "--pipe"},
                          {"--opt-in", "--confirm"});
        auto action = args[2];
        if (options.has("--pipe")) {
            Json request = {{"op", "baseline"}, {"host", options.require("--host")}};
            if (action == "learn" || action == "freeze" || action == "reset")
                request = {{"op", "baseline_change"},
                           {"host", options.require("--host")},
                           {"action", action},
                           {"opt_in", options.has("--opt-in")},
                           {"confirm", options.has("--confirm")},
                           {"duration_seconds",
                            options.integer("--duration", action == "learn" ? 3600 : 0, 0, 604800)}};
            else if (action != "show" && action != "status")
                throw std::runtime_error("live baseline pipe supports show/status/learn/freeze/reset; "
                                         "offline compare/export requires --db");
            std::cout << pipeRequest(options.require("--pipe"), request).dump(2) << '\n';
            return 0;
        }
        if (action == "learn" && options.has("--duration"))
            throw std::runtime_error("timed baseline learning requires --pipe to a running agent; --events "
                                     "is an explicit offline fixture path");
        StoreWorker store(options.require("--db"));
        BaselineEngine baseline(store, options.require("--host"),
                                options.integer("--minimum-samples", 20, 1, 100000));
        if (action == "learn") {
            baseline.learn(options.has("--opt-in"), options.integer("--duration", 0, 0, 604800));
            if (options.has("--events"))
                for (auto &e : readReplay(options.get("--events")))
                    baseline.observe(e);
            baseline.flush();
        } else if (action == "freeze")
            baseline.freeze();
        else if (action == "reset")
            baseline.reset(options.has("--confirm"));
        else if (action == "import")
            baseline.importData(readJsonFile(options.require("--input")), options.has("--confirm"));
        else if (action == "compare") {
            Json rows = Json::array();
            if (options.has("--events")) {
                for (const auto &e : readReplay(options.get("--events")))
                    rows.push_back({{"event_id", e.id}, {"comparison", baseline.compare(e)}});
                std::cout << rows.dump(2) << '\n';
            } else {
                auto window = options.get("--window", "24h");
                if (window.size() < 2 || window.size() > 6 ||
                    std::string("mhd").find(window.back()) == std::string::npos)
                    throw std::runtime_error("baseline window requires minutes/hours/days, for example 24h");
                int count = 0;
                auto parsed = std::from_chars(window.data(), window.data() + window.size() - 1, count);
                auto multiplier = window.back() == 'm' ? 60LL : window.back() == 'h' ? 3600LL : 86400LL;
                if (parsed.ec != std::errc{} || parsed.ptr != window.data() + window.size() - 1 ||
                    count < 1 || count * multiplier > 604800)
                    throw std::runtime_error(
                        "baseline comparison window must be positive and at most seven days");
                auto now = utcNow();
                Json filters = {{"host", options.get("--host")},
                                {"from", formatUtc(now - count * multiplier * 1000)},
                                {"to", formatUtc(now)}};
                int total = 0;
                for (int offset = 0; offset < 5000; offset += 500) {
                    auto page = store.call({{"op", "query"},
                                            {"table", "events"},
                                            {"filters", filters},
                                            {"limit", 500},
                                            {"offset", offset}});
                    total = page.at("total").get<int>();
                    for (const auto &document : page.at("rows")) {
                        auto event = document.get<SecurityEvent>();
                        rows.push_back(
                            {{"event_id", event.uniqueId}, {"comparison", baseline.compare(event)}});
                    }
                    if (offset + 500 >= total)
                        break;
                }
                std::cout << Json{{"window", window},
                                  {"mode", "stored observations; no new collection"},
                                  {"total", total},
                                  {"truncated", total > 5000},
                                  {"rows", rows}}
                                 .dump(2)
                          << '\n';
            }
            return 0;
        } else if (action == "export") {
            auto path = filesystemPath(options.require("--output"));
            if (std::filesystem::exists(path))
                throw std::runtime_error("baseline output exists");
            writeDocument(path, baseline.exportData());
        } else if (action != "show" && action != "status")
            throw std::runtime_error("expected baseline learn/freeze/reset/import/export/compare/show");
        store.call({{"op", "audit"},
                    {"author", "local CLI operator"},
                    {"data",
                     {{"operation", "baseline_" + action},
                      {"host_id", options.get("--host")},
                      {"opt_in", options.has("--opt-in")},
                      {"confirmed", options.has("--confirm")}}}});
        std::cout << baseline.exportData().dump(2) << '\n';
        return 0;
    }
    if (args[1] == "_yara-worker") {
        Arguments options(args, 2, {"--rules"});
        return yaraWorker(options.require("--rules"));
    }
    if (args[1] == "yara" && args.size() > 2) {
        if (args[2] == "validate") {
            Arguments options(args, 3, {"--rules"});
            YaraScanner scanner(options.get("--rules", "rules/yara"));
            std::cout << scanner.health().dump(2) << '\n';
            return 0;
        }
        if (args[2] == "scan") {
            Arguments options(args, 3,
                              {"--rules", "--file", "--path", "--timeout-seconds", "--max-file-mib"});
            YaraScanner scanner(
                options.get("--rules", "rules/yara"), options.integer("--timeout-seconds", 10, 1, 120),
                static_cast<std::uint64_t>(options.integer("--max-file-mib", 100, 1, 1024)) * 1048576);
            auto path = options.get("--file", options.get("--path"));
            if (path.empty())
                throw std::runtime_error("yara scan requires --file or --path");
            if (std::filesystem::is_directory(filesystemPath(path))) {
                Json results = Json::array();
                bool failed = false;
                for (const auto &entry : std::filesystem::recursive_directory_iterator(
                         filesystemPath(path), std::filesystem::directory_options::skip_permission_denied)) {
                    if (!entry.is_regular_file())
                        continue;
                    if (results.size() >= 128)
                        throw std::runtime_error("directory YARA scan exceeds 128 files; narrow the path");
                    if (!pathWithinRoot(entry.path().string(), path))
                        continue;
                    auto result = scanner.scan(entry.path().string());
                    failed |= result.value("status", std::string{}) != "complete";
                    results.push_back(result);
                }
                std::cout << Json{{"results", results}, {"files", results.size()}, {"limit", 128}}.dump(2)
                          << '\n';
                return failed ? 2 : 0;
            }
            auto result = scanner.scan(path);
            std::cout << result.dump(2) << '\n';
            return result.value("status", std::string{}) == "complete" ? 0 : 2;
        }
        throw std::runtime_error("expected yara validate/scan");
    }
    if (args[1] == "rules" && args.size() > 2 && args[2] != "validate") {
        if (args[2] == "list") {
            Arguments options(args, 3, {"--dir"});
            auto engine = RuleEngine::load(options.get("--dir", "rules"));
            Json rows = Json::array();
            for (const auto &r : engine.rules())
                rows.push_back({{"id", r.id},
                                {"name", r.name},
                                {"enabled", r.enabled},
                                {"type", r.type},
                                {"score", r.score},
                                {"confidence", r.confidence},
                                {"attack", r.attack},
                                {"false_positives", r.falsePositives},
                                {"license", r.license},
                                {"source", r.source}});
            std::cout << rows.dump(2) << '\n';
            return 0;
        }
        if (args[2] == "test") {
            Arguments options(args, 3, {"--dir", "--events", "--expect"});
            auto engine = RuleEngine::load(options.get("--dir", "rules"));
            auto result = testRules(engine, readReplay(options.require("--events")));
            bool valid = true;
            if (options.has("--expect")) {
                auto expected = readJsonFile(options.get("--expect"));
                valid = expected == result["rule_counts"];
                result["expected_counts"] = expected;
                result["passed"] = valid;
            }
            std::cout << result.dump(2) << '\n';
            return valid ? 0 : 2;
        }
        if (args[2] == "import-sigma") {
            Arguments options(args, 3, {"--input", "--out"});
            auto input = options.require("--input");
            std::ifstream file(filesystemPath(input), std::ios::binary);
            file.seekg(0, std::ios::end);
            auto length = file.tellg();
            if (length < 0 || length > 262144)
                throw std::runtime_error("Sigma input unreadable or larger than 256 KiB");
            file.seekg(0);
            std::string yaml(static_cast<std::size_t>(length), '\0');
            file.read(yaml.data(), length);
            auto rule = importSigma(yaml, input);
            auto path = filesystemPath(options.require("--out"));
            if (std::filesystem::exists(path))
                throw std::runtime_error("Sigma output exists; choose a new path");
            std::ofstream out(path, std::ios::binary);
            out << rule.dump(2) << '\n';
            if (!out)
                throw std::runtime_error("Sigma output write failed");
            std::cout << rule.dump(2) << '\n';
            return 0;
        }
        throw std::runtime_error("unsupported rules action; use validate/list/test/import-sigma");
    }
#ifdef _WIN32
    if (args[1] == "eventlog" && args.size() > 2 && args[2] == "import") {
        Arguments options(args, 3, {"--input", "--output"});
        auto events = importEventLog(options.require("--input"));
        auto output = options.require("--output");
        privateDirectory(output, true);
        auto host = stableHostId(), session = newUuid();
        std::ofstream file(filesystemPath(output) / "events.jsonl", std::ios::binary);
        EventId sequence = 0;
        for (auto &e : events) {
            e.id = ++sequence;
            e.uniqueId = host + "/" + session + "/" + std::to_string(e.id);
            e.hostId = host;
            e.sessionId = session;
            file << Json(e).dump() << '\n';
        }
        file.close();
        if (!file)
            throw std::runtime_error("import output failed");
        writeDocument(filesystemPath(output) / "manifest.json", evidenceManifest(output, session));
        std::cout << Json{{"events", events.size()},
                          {"output", output},
                          {"host_id", host},
                          {"session_id", session}}
                         .dump(2)
                  << '\n';
        return 0;
    }
#endif
    if (args[1] == "snapshot") {
        if (std::find(args.begin(), args.end(), "--help") != args.end()) {
            std::cout << "snapshot --output NEW_DIRECTORY [--include-evtx]\nRead-only metadata; no private "
                         "file copies. EVTX exports are explicit and size bounded.\n";
            return 0;
        }
        Arguments options(args, 2, {"--output"}, {"--include-evtx"});
        auto result = forensicSnapshot(options.require("--output"), options.has("--include-evtx"));
        std::cout << result.dump(2) << '\n';
        return 0;
    }
    if (args[1] == "evidence") {
        if (args.size() < 3 || args[2] != "verify")
            throw std::runtime_error("expected evidence verify --manifest FILE");
        if (std::find(args.begin(), args.end(), "--help") != args.end()) {
            std::cout << "evidence verify --manifest FILE\n";
            return 0;
        }
        Arguments options(args, 3, {"--manifest"});
        auto result = verifyEvidence(options.require("--manifest"));
        std::cout << result.dump(2) << '\n';
        return result.at("valid").get<bool>() ? 0 : 2;
    }
    if (args[1] == "artifact") {
        if (args.size() < 3 || args[2] != "inspect")
            throw std::runtime_error("expected artifact inspect --path FILE");
        if (std::find(args.begin(), args.end(), "--help") != args.end()) {
            std::cout << "artifact inspect --path FILE [--max-file-mib 100]\nLocal read-only SHA256 and "
                         "offline Authenticode.\n";
            return 0;
        }
        Arguments options(args, 3, {"--path", "--max-file-mib"});
        auto result = artifactMetadata(
            options.require("--path"),
            static_cast<std::uint64_t>(options.integer("--max-file-mib", 100, 1, 1024)) * 1024 * 1024);
        std::cout << result.dump(2) << '\n';
        return result["hash"]["status"] == "complete" ? 0 : 2;
    }
    return {};
}
} // namespace irforge
