#include "irforge/detection/RuleEngine.hpp"
#include <algorithm>
#include <filesystem>
#include <set>
#include <stdexcept>
namespace irforge {
namespace {
const std::set<std::string> fields = {"process.name",
                                      "process.command_line",
                                      "process.image_path",
                                      "process.parent.name",
                                      "process.initial_enumeration",
                                      "network.remote_class",
                                      "network.state",
                                      "network.first_snapshot",
                                      "network.change",
                                      "network.owner_verified",
                                      "registry.is_run",
                                      "registry.is_service",
                                      "registry.new_data",
                                      "registry.user_writable",
                                      "registry.service_start",
                                      "registry.actor_known"};
bool predicate(const Predicate &p, const SecurityEvent &e, const ProcessTracker &t) {
    auto s = RuleEngine::field(p.field, e, t);
    if (!s)
        return false;
    auto v = lower(*s);
    if (p.op == "exists")
        return true;
    if (p.op == "in_ci" || p.op == "contains_any_ci") {
        for (const auto &item : p.value) {
            auto x = lower(item.get<std::string>());
            if (p.op == "in_ci" ? v == x : v.find(x) != std::string::npos)
                return true;
        }
        return false;
    }
    auto x = lower(p.value.get<std::string>());
    if (p.op == "equals_ci")
        return v == x;
    if (p.op == "contains_ci")
        return v.find(x) != std::string::npos;
    return v.starts_with(x);
}
} // namespace
Rule RuleEngine::parse(const Json &j) {
    if (!j.is_object() || j.at("schema_version") != 1)
        throw std::runtime_error("unsupported rule schema");
    const std::set<std::string> keys = {
        "schema_version", "id",  "name", "description", "severity", "type",           "enabled",
        "event_type",     "all", "any",  "score",       "requires", "window_seconds", "linkage"};
    for (auto it = j.begin(); it != j.end(); ++it)
        if (!keys.contains(it.key()))
            throw std::runtime_error("unknown rule field " + it.key());
    Rule r;
    if (!j.at("score").is_number_integer())
        throw std::runtime_error("score must be an integer");
    r.id = j.at("id").get<std::string>();
    r.name = j.at("name").get<std::string>();
    r.description = j.at("description").get<std::string>();
    r.severity = j.at("severity").get<std::string>();
    r.type = j.value("type", std::string("event"));
    r.enabled = j.value("enabled", true);
    r.score = j.at("score").get<int>();
    if (r.id.empty() || r.id.size() > 64 || r.name.size() > 256 || r.description.size() > 4096 ||
        r.score < 0 || r.score > 100 ||
        !std::set<std::string>{"informational", "low", "medium", "high", "critical"}.contains(r.severity))
        throw std::runtime_error("invalid rule ID/name/score/severity");
    if (r.type == "correlation") {
        if (!j.at("window_seconds").is_number_integer())
            throw std::runtime_error("window_seconds must be an integer");
        r.requiresRules = j.at("requires").get<std::vector<std::string>>();
        r.linkage = j.at("linkage").get<std::string>();
        r.windowSeconds = j.at("window_seconds").get<int>();
        if (std::set<std::string>(r.requiresRules.begin(), r.requiresRules.end()).size() !=
            r.requiresRules.size())
            throw std::runtime_error("duplicate correlation dependency");
        if (r.requiresRules.size() < 2 || r.requiresRules.size() > 16 || r.windowSeconds < 1 ||
            r.windowSeconds > 3600 || (r.linkage != "same_process" && r.linkage != "lineage_path"))
            throw std::runtime_error("invalid correlation requirements/window/linkage");
        if (j.contains("event_type") || j.contains("all") || j.contains("any"))
            throw std::runtime_error("correlation rules cannot have event predicates");
        return r;
    }
    if (r.type != "event")
        throw std::runtime_error("unsupported rule type");
    if (j.contains("requires") || j.contains("window_seconds") || j.contains("linkage"))
        throw std::runtime_error("event rule cannot have correlation fields");
    auto types = j.at("event_type");
    if (!types.is_array())
        types = Json::array({types});
    if (types.empty() || types.size() > 10)
        throw std::runtime_error("event_type needs 1..10 types");
    for (const auto &type : types)
        r.eventTypes.push_back(parseEventType(type.get<std::string>()));
    r.eventType = r.eventTypes.front();
    auto parsePreds = [&](const char *key, std::vector<Predicate> &out) {
        if (!j.contains(key))
            return;
        const auto &a = j.at(key);
        if (!a.is_array() || a.size() > 32)
            throw std::runtime_error("predicates must be an array of at most 32");
        for (const auto &p : a) {
            if (!p.is_object() || p.size() > 3)
                throw std::runtime_error("invalid predicate object");
            for (auto it = p.begin(); it != p.end(); ++it)
                if (it.key() != "field" && it.key() != "operator" && it.key() != "value")
                    throw std::runtime_error("unknown predicate field " + it.key());
            Predicate x{p.at("field").get<std::string>(), p.at("operator").get<std::string>(),
                        p.value("value", Json(nullptr))};
            if (!fields.contains(x.field))
                throw std::runtime_error("unsupported field " + x.field);
            if (!std::set<std::string>{"equals_ci", "in_ci", "contains_ci", "contains_any_ci",
                                       "starts_with_ci", "exists"}
                     .contains(x.op))
                throw std::runtime_error("unsupported operator " + x.op);
            auto str = [](const Json &v) {
                if (!v.is_string() || v.get_ref<const std::string &>().empty() ||
                    v.get_ref<const std::string &>().size() > 4096)
                    throw std::runtime_error("predicate values must be nonempty bounded strings");
            };
            if (x.op == "in_ci" || x.op == "contains_any_ci") {
                if (!x.value.is_array() || x.value.empty() || x.value.size() > 64)
                    throw std::runtime_error("operator requires nonempty bounded array");
                for (const auto &v : x.value)
                    str(v);
            } else if (x.op != "exists")
                str(x.value);
            // Field paths must belong to the rule's payload (process context is valid on TCP).
            for (auto eventType : r.eventTypes) {
                bool proc = eventType == EventType::ProcessStart || eventType == EventType::ProcessExit;
                bool net = eventType == EventType::TcpConnectionObserved ||
                           eventType == EventType::TcpConnectionClosed;
                if ((x.field.starts_with("network.") && !net) ||
                    (x.field.starts_with("registry.") &&
                     (proc || net || eventType == EventType::MonitorStatus)) ||
                    (x.field.starts_with("process.") && !proc && !net))
                    throw std::runtime_error("field incompatible with event_type: " + x.field);
            }
            out.push_back(std::move(x));
        }
    };
    parsePreds("all", r.all);
    parsePreds("any", r.any);
    if (r.all.empty() && r.any.empty())
        throw std::runtime_error("rule needs all/any predicates");
    return r;
}
RuleEngine RuleEngine::load(const std::string &dir) {
    std::vector<std::filesystem::path> paths;
    for (const auto &f : std::filesystem::directory_iterator(filesystemPath(dir)))
        if (f.is_regular_file() && f.path().extension() == ".json")
            paths.push_back(f.path());
    std::sort(paths.begin(), paths.end());
    if (paths.empty() || paths.size() > 256)
        throw std::runtime_error(dir + ": expected 1..256 JSON rule files");
    std::vector<Rule> rules;
    std::set<std::string> ids;
    for (const auto &path : paths) {
        auto u = path.u8string();
        std::string filename(u.begin(), u.end());
        auto j = readJsonFile(filename);
        if (!j.is_array())
            j = Json::array({j});
        if (j.size() > 256)
            throw std::runtime_error(filename + ": too many rules");
        for (const auto &row : j) {
            try {
                auto r = parse(row);
                if (!ids.insert(r.id).second)
                    throw std::runtime_error("duplicate ID");
                rules.push_back(std::move(r));
            } catch (const std::exception &ex) {
                auto id = row.is_object() && row.contains("id") && row["id"].is_string()
                              ? row["id"].get<std::string>()
                              : "unknown";
                throw std::runtime_error(filename + " [" + id + "]: " + ex.what());
            }
        }
    }
    if (rules.size() > 512)
        throw std::runtime_error("more than 512 rules");
    for (const auto &r : rules)
        for (const auto &id : r.requiresRules) {
            auto found = std::find_if(rules.begin(), rules.end(), [&](const auto &other) {
                return other.id == id && other.type == "event";
            });
            if (found == rules.end())
                throw std::runtime_error(r.id + ": missing atomic dependency " + id);
        }
    return RuleEngine(std::move(rules));
}
std::optional<std::string> RuleEngine::field(const std::string &f, const SecurityEvent &e,
                                             const ProcessTracker &t) {
    auto p = std::get_if<ProcessPayload>(&e.payload);
    auto n = std::get_if<TcpPayload>(&e.payload);
    const ProcessRecord *r = p   ? t.resolve(p->identity.pid, e.timestampUtc, p->identity.creationTime100ns)
                             : n ? t.resolve(n->ownerPid, e.timestampUtc, n->ownerCreationTime100ns)
                                 : nullptr;
    if (f == "process.name") {
        if (r && r->data.imagePath)
            return baseName(*r->data.imagePath);
        if (p && p->imagePath)
            return baseName(*p->imagePath);
    }
    if (f == "process.image_path") {
        if (r)
            return r->data.imagePath;
        if (p)
            return p->imagePath;
    }
    if (f == "process.command_line" && p)
        return p->commandLine;
    if (f == "process.initial_enumeration" && p)
        return p->initialEnumeration ? "true" : "false";
    if (f == "process.parent.name" && r) {
        auto parent = t.parent(*r);
        if (parent && parent->data.imagePath)
            return baseName(*parent->data.imagePath);
    }
    if (n) {
        if (f == "network.remote_class")
            return addressClass(n->remoteAddress);
        if (f == "network.state")
            return lower(n->state);
        if (f == "network.first_snapshot")
            return n->firstSnapshot ? "true" : "false";
        if (f == "network.change")
            return n->change;
        if (f == "network.owner_verified")
            return r && n->ownerCreationTime100ns &&
                           r->data.identity.creationTime100ns == n->ownerCreationTime100ns
                       ? "true"
                       : "false";
    }
    if (auto x = std::get_if<RegistryPayload>(&e.payload)) {
        auto k = normalizePath(x->keyPath);
        auto leaf = baseName(k);
        if (f == "registry.is_run")
            return (k.find("software\\microsoft\\windows\\currentversion\\") == 0 &&
                    (leaf == "run" || leaf == "runonce"))
                       ? "true"
                       : "false";
        if (f == "registry.is_service")
            return k.starts_with("system\\currentcontrolset\\services\\") ? "true" : "false";
        if (f == "registry.new_data" && x->newData)
            return x->newData->text;
        if (f == "registry.user_writable") {
            auto path = x->serviceImage;
            if (!path && x->newData)
                path = x->newData->text;
            return path ? (userWritablePath(*path) ? "true" : "false") : std::optional<std::string>{};
        }
        if (f == "registry.service_start" && x->serviceStart)
            return std::to_string(*x->serviceStart);
        if (f == "registry.actor_known")
            return x->actorPid ? "true" : "false";
    }
    return {};
}
std::vector<Match> RuleEngine::evaluate(const SecurityEvent &e, const ProcessTracker &t) const {
    std::vector<Match> out;
    if (auto p = std::get_if<ProcessPayload>(&e.payload); p && p->initialEnumeration)
        return out;
    for (const auto &r : rules_) {
        if (!r.enabled || r.type != "event" ||
            std::find(r.eventTypes.begin(), r.eventTypes.end(), e.type) == r.eventTypes.end())
            continue;
        if (!std::all_of(r.all.begin(), r.all.end(), [&](const auto &p) { return predicate(p, e, t); }))
            continue;
        if (!r.any.empty() &&
            !std::any_of(r.any.begin(), r.any.end(), [&](const auto &p) { return predicate(p, e, t); }))
            continue;
        Match match{r.id, r.description, "", r.score, {e.id}, e.timestampUtc, e.timestampUtc};
        if (std::any_of(r.all.begin(), r.all.end(),
                        [](const auto &p) { return p.field == "process.parent.name"; }) ||
            std::any_of(r.any.begin(), r.any.end(),
                        [](const auto &p) { return p.field == "process.parent.name"; })) {
            auto process = std::get_if<ProcessPayload>(&e.payload);
            auto row = process ? t.resolve(process->identity.pid, e.timestampUtc,
                                           process->identity.creationTime100ns)
                               : nullptr;
            auto parent = row ? t.parent(*row) : nullptr;
            if (parent)
                match.eventIds.push_back(parent->startEventId);
        }
        out.push_back(std::move(match));
    }
    return out;
}
} // namespace irforge
