#include "irforge/replay/ReplayEngine.hpp"
#include <algorithm>
#include <catch2/catch_test_macros.hpp>
using namespace irforge;
namespace {
std::string root = IRFORGE_SOURCE_DIR;
RuleEngine rules() { return RuleEngine::load(root + "/rules"); }
std::vector<SecurityEvent> fixture(const std::string &name) {
    return readReplay(root + "/tests/fixtures/" + name + ".jsonl");
}
std::vector<Incident> detect(const std::vector<SecurityEvent> &events) {
    Correlator c(rules(), Config{});
    for (const auto &e : events)
        c.ingest(e);
    std::vector<Incident> out;
    for (const auto &[id, i] : c.incidents())
        out.push_back(i);
    return out;
}
bool has(const Incident &i, const std::string &id) {
    return std::any_of(i.matches.begin(), i.matches.end(), [&](const auto &m) { return m.ruleId == id; });
}
} // namespace
TEST_CASE("rule validation rejects unsupported operators fields duplicates and malformed JSON") {
    auto j = readJsonFile(root + "/rules/process.json")[1];
    REQUIRE(RuleEngine::parse(j).id == "PROC-002");
    j["all"][0]["operator"] = "regex";
    REQUIRE_THROWS(RuleEngine::parse(j));
    j["all"][0]["operator"] = "equals_ci";
    j["all"][0]["field"] = "not.a.field";
    REQUIRE_THROWS(RuleEngine::parse(j));
    auto dir = std::filesystem::temp_directory_path() / "irforge-invalid-rules";
    std::filesystem::create_directories(dir);
    {
        std::ofstream f(dir / "bad.json");
        f << "not json";
    }
    REQUIRE_THROWS(RuleEngine::load(dir.string()));
    auto valid = readJsonFile(root + "/rules/process.json")[1];
    {
        std::ofstream f(dir / "bad.json");
        f << Json::array({valid, valid});
    }
    REQUIRE_THROWS(RuleEngine::load(dir.string()));
    std::filesystem::remove(dir / "bad.json");
    std::filesystem::remove(dir);
}
TEST_CASE("Office encoded shell network chain has transparent once-only score") {
    auto events = fixture("suspicious_chain");
    auto incidents = detect(events);
    REQUIRE(incidents.size() == 1);
    auto i = incidents[0];
    REQUIRE(has(i, "PROC-001"));
    REQUIRE(has(i, "PROC-002"));
    REQUIRE(has(i, "NET-001"));
    REQUIRE(has(i, "CORR-001"));
    REQUIRE(i.score == 100);
    REQUIRE(i.confidence == "high");
    auto repeated = events.back();
    repeated.id = 99;
    events.push_back(repeated);
    auto again = detect(events);
    REQUIRE(again[0].score == 100);
    REQUIRE(again[0].matches.size() == 4);
}
TEST_CASE("missing command line initial rundown and benign events cannot cause shell detections") {
    auto events = fixture("suspicious_chain");
    auto &shell = std::get<ProcessPayload>(events[1].payload);
    shell.commandLine.reset();
    auto result = detect(events);
    REQUIRE_FALSE(has(result[0], "PROC-002"));
    REQUIRE_FALSE(has(result[0], "CORR-001"));
    shell.initialEnumeration = true;
    result = detect(events);
    for (const auto &i : result)
        REQUIRE_FALSE(has(i, "PROC-001"));
    for (const auto &i : detect(fixture("benign")))
        REQUIRE(i.score < 60);
}
TEST_CASE("case insensitive predicates and absent fields") {
    auto events = fixture("suspicious_chain");
    auto &p = std::get<ProcessPayload>(events[1].payload);
    p.imagePath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\POWERSHELL.EXE";
    p.commandLine = "POWERSHELL.EXE -ENC AAAA";
    REQUIRE(has(detect(events)[0], "PROC-002"));
    p.imagePath.reset();
    p.commandLine.reset();
    REQUIRE(detect(events).empty());
}
TEST_CASE("process tracker separates reused PIDs and rejects invalid old parent") {
    auto events = fixture("pid_reuse");
    ProcessTracker t;
    for (const auto &e : events)
        t.observe(e);
    REQUIRE(t.size() == 3);
    REQUIRE(t.resolve(200, events.back().timestampUtc, 2000) == nullptr);
    REQUIRE(t.resolve(200, events.back().timestampUtc, 3000) != nullptr);
    auto incidents = detect(events);
    for (const auto &i : incidents)
        REQUIRE_FALSE(has(i, "CORR-001"));
    t.prune(events.back().timestampUtc + 1);
    REQUIRE(t.size() == 0);
}
TEST_CASE("unknown socket identity and another process do not complete correlation") {
    auto events = fixture("suspicious_chain");
    auto &n = std::get<TcpPayload>(events[2].payload);
    n.ownerCreationTime100ns.reset();
    auto a = detect(events);
    REQUIRE_FALSE(has(a[0], "CORR-001"));
    REQUIRE(a[0].confidence == "low");
    n.ownerPid = 100;
    n.ownerCreationTime100ns = 1000;
    a = detect(events);
    REQUIRE_FALSE(has(a[0], "CORR-001"));
    n.ownerPid = 200;
    n.ownerCreationTime100ns = 2000;
    n.firstSnapshot = true;
    a = detect(events);
    REQUIRE_FALSE(has(a[0], "NET-001"));
}
TEST_CASE("event-time out of order arrivals converge to same relevant incident") {
    auto events = fixture("suspicious_chain");
    auto expected = detect(events);
    std::reverse(events.begin(), events.end());
    auto actual = detect(events);
    REQUIRE(actual.size() == expected.size());
    REQUIRE(actual[0].score == expected[0].score);
    REQUIRE(actual[0].id == expected[0].id);
    REQUIRE(has(actual[0], "CORR-001"));
}
TEST_CASE("unattributed registry stays standalone and related paths are explicitly weak") {
    auto events = fixture("suspicious_chain");
    auto registry = fixture("unattributed_registry");
    events.push_back(registry[0]);
    auto out = detect(events);
    REQUIRE(out.size() == 2);
    for (const auto &i : out)
        if (has(i, "PERS-001")) {
            REQUIRE_FALSE(i.root);
            REQUIRE(i.confidence == "low");
            REQUIRE_FALSE(has(i, "CORR-002"));
        }
    auto &r = std::get<RegistryPayload>(events.back().payload);
    r.newData->text = std::get<ProcessPayload>(events[1].payload).imagePath;
    out = detect(events);
    REQUIRE(out.size() == 1);
    REQUIRE(has(out[0], "CORR-002"));
    REQUIRE(out[0].confidence == "low");
    REQUIRE(out[0].notes.size() >= 2);
    std::reverse(events.begin(), events.end());
    out = detect(events);
    REQUIRE(has(out[0], "CORR-002"));
}
TEST_CASE("all persistence rules match only selected changes and service context") {
    auto event = fixture("unattributed_registry")[0];
    auto out = detect({event});
    REQUIRE(has(out[0], "PERS-001"));
    REQUIRE(has(out[0], "PERS-002"));
    event.type = EventType::RegistryValueModified;
    out = detect({event});
    REQUIRE_FALSE(has(out[0], "PERS-001"));
    REQUIRE(has(out[0], "PERS-002"));
    auto &p = std::get<RegistryPayload>(event.payload);
    p.keyPath = "SYSTEM\\CurrentControlSet\\Services\\Lab";
    p.serviceImage = "C:\\Users\\Lab\\service.exe";
    p.serviceStart = 2;
    out = detect({event});
    REQUIRE(has(out[0], "PERS-003"));
    p.serviceStart = 3;
    REQUIRE(detect({event}).empty());
    p.serviceStart = 2;
    p.serviceImage = "C:\\Windows\\System32\\service.exe";
    REQUIRE(detect({event}).empty());
}
TEST_CASE("correlation window and active scores expire deterministically") {
    auto events = fixture("suspicious_chain");
    events[2].timestampUtc += 61000;
    auto out = detect(events);
    REQUIRE_FALSE(has(out[0], "CORR-001"));
    Correlator c(rules(), Config{});
    for (const auto &e : fixture("suspicious_chain"))
        c.ingest(e);
    auto expired = c.expire(events.back().timestampUtc + 301000);
    REQUIRE(c.incidents().empty());
    REQUIRE_FALSE(expired.empty());
    REQUIRE(expired[0].status == "expired");
}
TEST_CASE("risk engine deduplicates clamps and gives stable severity") {
    Incident i;
    i.matches = {{"a", "reason", "a", 80, {1}, 0, 0},
                 {"a", "duplicate", "a", 80, {2}, 0, 0},
                 {"b", "reason", "b", 35, {3}, 0, 0}};
    scoreIncident(i);
    REQUIRE(i.score == 100);
    REQUIRE(severity(0) == "informational");
    REQUIRE(severity(20) == "low");
    REQUIRE(severity(40) == "medium");
    REQUIRE(severity(60) == "high");
    REQUIRE(severity(80) == "critical");
}
TEST_CASE("history is bounded and evictions are visible") {
    Config config;
    config.max_history_events = 2;
    Correlator c(rules(), config);
    for (const auto &e : fixture("suspicious_chain"))
        c.ingest(e);
    REQUIRE(c.evicted() == 1);
}
TEST_CASE("predicate AND OR exists and strict schema validation") {
    auto j = readJsonFile(root + "/rules/process.json")[1];
    j["all"] = Json::array({{{"field", "process.name"}, {"operator", "starts_with_ci"}, {"value", "power"}},
                            {{"field", "process.command_line"}, {"operator", "exists"}}});
    j["any"] = Json::array(
        {{{"field", "process.name"}, {"operator", "equals_ci"}, {"value", "cmd.exe"}},
         {{"field", "process.command_line"}, {"operator", "contains_ci"}, {"value", "encodedcommand"}}});
    RuleEngine engine({RuleEngine::parse(j)});
    auto events = fixture("suspicious_chain");
    ProcessTracker tracker;
    for (const auto &e : events)
        tracker.observe(e);
    REQUIRE(engine.evaluate(events[1], tracker).size() == 1);
    std::get<ProcessPayload>(events[1].payload).commandLine.reset();
    REQUIRE(engine.evaluate(events[1], tracker).empty());
    j["score"] = 1.5;
    REQUIRE_THROWS(RuleEngine::parse(j));
    j["score"] = 25;
    j["event_type"] = Json::array({"process_start", "registry_value_added"});
    REQUIRE_THROWS(RuleEngine::parse(j));
    j["event_type"] = "process_start";
    j["all"][0]["unexpected"] = true;
    REQUIRE_THROWS(RuleEngine::parse(j));
    auto correlation = readJsonFile(root + "/rules/correlation.json")[0];
    correlation["requires"] = Json::array({"PROC-001", "PROC-001"});
    REQUIRE_THROWS(RuleEngine::parse(correlation));
}
TEST_CASE("alerts suppress identical states permit escalation and preserve existing output") {
    auto dir = filesystemPath(root) / "build" / ("alert-test-" + std::to_string(utcNow()));
    {
        JsonlWriter writer(dir.string());
        AlertManager alerts(writer, "medium", true);
        Incident i;
        i.id = "test-chain";
        i.first = i.last = 1000;
        i.matches = {{"PROC-001", "observed parent", "a", 35, {1}, 1000, 1000},
                     {"PROC-002", "encoded argument", "b", 25, {2}, 1000, 1000}};
        scoreIncident(i);
        alerts.update({i}, 1000);
        alerts.update({i}, 1001);
        REQUIRE(alerts.count() == 1);
        i.matches.push_back({"CORR-001", "complete chain", "c", 30, {1, 2, 3}, 1000, 1002});
        scoreIncident(i);
        alerts.update({i}, 1002);
        REQUIRE(alerts.count() == 2);
        writer.flush();
        REQUIRE_THROWS(JsonlWriter(dir.string()));
    }
    std::ifstream f(dir / "alerts.jsonl");
    std::string line;
    int count = 0;
    while (std::getline(f, line)) {
        auto j = Json::parse(line);
        REQUIRE(j["matched_rules"].is_array());
        REQUIRE(j["evidence_event_ids"].size() >= 2);
        ++count;
    }
    f.close();
    REQUIRE(count == 2);
    std::filesystem::remove(dir / "events.jsonl");
    std::filesystem::remove(dir / "alerts.jsonl");
    std::filesystem::remove(dir);
}
TEST_CASE("malformed replay rejects duplicate IDs bad endpoints and oversized lines") {
    auto events = fixture("suspicious_chain");
    auto file = filesystemPath(root) / "build" / "malformed-replay.jsonl";
    {
        std::ofstream f(file);
        f << Json(events[0]) << '\n' << Json(events[0]) << '\n';
    }
    REQUIRE_THROWS(readReplay(file.string()));
    auto j = Json(events[2]);
    j["payload"]["remote_port"] = 70000;
    {
        std::ofstream f(file);
        f << j << '\n';
    }
    REQUIRE_THROWS(readReplay(file.string()));
    j = Json(events[2]);
    j["payload"]["remote_address"] = "bad-ip";
    {
        std::ofstream f(file);
        f << j << '\n';
    }
    REQUIRE_THROWS(readReplay(file.string()));
    {
        std::ofstream f(file);
        f << std::string(1048577, 'x');
    }
    REQUIRE_THROWS(readReplay(file.string()));
    std::filesystem::remove(file);
}
TEST_CASE("expired parents and independent process generations cannot be joined") {
    auto events = fixture("suspicious_chain");
    auto end = events[0];
    end.id = 8;
    end.type = EventType::ProcessExit;
    end.timestampUtc = events[0].timestampUtc + 500;
    events.insert(events.begin() + 1, end);
    auto out = detect(events);
    REQUIRE(out.size() == 1);
    REQUIRE_FALSE(has(out[0], "PROC-001"));
    REQUIRE_FALSE(has(out[0], "CORR-001"));
    auto second = fixture("suspicious_chain")[1];
    second.id = 9;
    std::get<ProcessPayload>(second.payload).identity = {201, 2001, 0};
    second.timestampUtc += 1;
    events = fixture("suspicious_chain");
    std::get<ProcessPayload>(events[1].payload).commandLine.reset();
    events.push_back(second);
    out = detect(events);
    REQUIRE_FALSE(has(out[0], "CORR-001"));
}
