#include "irforge/detection/RuleEngine.hpp"
#include "irforge/detection/AttackMapper.hpp"
#include <algorithm>
#include <charconv>
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
                                      "registry.actor_known",
                                      "process.parent.image_path",
                                      "file.path",
                                      "file.action",
                                      "artifact.sha256",
                                      "artifact.signature.status",
                                      "inventory.key",
                                      "inventory.image",
                                      "inventory.user_writable",
                                      "inventory.action",
                                      "event.source",
                                      "event.attribution_confidence",
                                      "logon.result",
                                      "logon.type",
                                      "dns.query",
                                      "yara.rule",
                                      "baseline.feature",
                                      "ti.verdict"};
bool predicate(const Predicate &p, const SecurityEvent &e, const ProcessTracker &t) {
    auto s = RuleEngine::field(p.field, e, t);
    if (!s)
        return false;
    if (p.op == "exists")
        return true;
    if (p.op == "range") {
        double n{};
        auto parsed = std::from_chars(s->data(), s->data() + s->size(), n);
        return parsed.ec == std::errc{} && parsed.ptr == s->data() + s->size() &&
               n >= p.value[0].get<double>() && n <= p.value[1].get<double>();
    }
    const bool ci = p.op.ends_with("_ci");
    auto v = ci ? lower(*s) : *s;
    if (p.op == "in_ci" || p.op == "contains_any_ci") {
        for (const auto &item : p.value) {
            auto x = lower(item.get<std::string>());
            if (p.op == "in_ci" ? v == x : v.find(x) != std::string::npos)
                return true;
        }
        return false;
    }
    auto x = p.value.get<std::string>();
    if (ci)
        x = lower(x);
    if (p.op == "equals_ci" || p.op == "equals")
        return v == x;
    if (p.op == "contains_ci" || p.op == "contains")
        return v.find(x) != std::string::npos;
    if (p.op == "ends_with_ci" || p.op == "ends_with")
        return v.ends_with(x);
    return v.starts_with(x);
}
void validateCondition(const Json &j, int depth, int &nodes) {
    if (depth > 8 || ++nodes > 128 || !j.is_object())
        throw std::runtime_error("condition exceeds depth/node bounds or is not an object");
    if (j.contains("and") || j.contains("or") || j.contains("not")) {
        if (j.size() != 1)
            throw std::runtime_error("condition group has unknown keys");
        if (j.contains("not")) {
            validateCondition(j["not"], depth + 1, nodes);
            return;
        }
        const auto &a = j.contains("and") ? j["and"] : j["or"];
        if (!a.is_array() || a.empty() || a.size() > 32)
            throw std::runtime_error("condition group needs 1..32 children");
        for (const auto &c : a)
            validateCondition(c, depth + 1, nodes);
        return;
    }
    if (j.size() > 3 || !j.contains("field") || !j.contains("operator"))
        throw std::runtime_error("invalid condition leaf");
    for (auto it = j.begin(); it != j.end(); ++it)
        if (it.key() != "field" && it.key() != "operator" && it.key() != "value")
            throw std::runtime_error("unknown condition key");
    auto f = j.at("field").get<std::string>(), op = j.at("operator").get<std::string>();
    if (!fields.contains(f))
        throw std::runtime_error("unsupported field " + f);
    if (!std::set<std::string>{"equals", "equals_ci", "contains", "contains_ci", "starts_with",
                               "starts_with_ci", "ends_with", "ends_with_ci", "in_ci", "contains_any_ci",
                               "range", "exists"}
             .contains(op))
        throw std::runtime_error("unsupported operator " + op);
    if (op == "exists") {
        if (j.contains("value") && !j["value"].is_null())
            throw std::runtime_error("exists has no value");
        return;
    }
    const auto &v = j.at("value");
    if (op == "range") {
        if (!v.is_array() || v.size() != 2 || !v[0].is_number() || !v[1].is_number() ||
            v[0].get<double>() > v[1].get<double>())
            throw std::runtime_error("invalid numeric range");
        return;
    }
    auto string = [](const Json &x) {
        if (!x.is_string() || x.get_ref<const std::string &>().empty() ||
            x.get_ref<const std::string &>().size() > 4096)
            throw std::runtime_error("condition value must be a bounded nonempty string");
    };
    if (op == "in_ci" || op == "contains_any_ci") {
        if (!v.is_array() || v.empty() || v.size() > 64)
            throw std::runtime_error("condition needs bounded array");
        for (const auto &x : v)
            string(x);
    } else
        string(v);
}
bool condition(const Json &j, const SecurityEvent &e, const ProcessTracker &t) {
    if (j.contains("and"))
        return std::all_of(j["and"].begin(), j["and"].end(),
                           [&](const auto &c) { return condition(c, e, t); });
    if (j.contains("or"))
        return std::any_of(j["or"].begin(), j["or"].end(), [&](const auto &c) { return condition(c, e, t); });
    if (j.contains("not"))
        return !condition(j["not"], e, t);
    return predicate(
        {j["field"].get<std::string>(), j["operator"].get<std::string>(), j.value("value", Json(nullptr))}, e,
        t);
}
} // namespace
Rule RuleEngine::parse(const Json &j) {
    if (!j.is_object() || (j.at("schema_version") != 1 && j.at("schema_version") != 2))
        throw std::runtime_error("unsupported rule schema");
    std::set<std::string> keys = {"schema_version", "id",       "name",           "description", "severity",
                                  "type",           "enabled",  "event_type",     "all",         "any",
                                  "score",          "requires", "window_seconds", "linkage"};
    const bool v2 = j.at("schema_version") == 2;
    if (v2)
        for (const auto *k :
             {"condition", "attack", "event_sources", "false_positives", "license", "source", "confidence"})
            keys.insert(k);
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
    if (v2) {
        r.attack = j.value("attack", std::vector<std::string>{});
        AttackMapper::validate(r.attack);
        r.eventSources = j.value("event_sources", std::vector<std::string>{});
        r.falsePositives = j.value("false_positives", std::vector<std::string>{});
        r.license = j.value("license", std::string{});
        r.source = j.value("source", std::string{});
        r.confidence = j.value("confidence", std::string("medium"));
        if (r.attack.size() > 16 || r.eventSources.size() > 16 || r.falsePositives.size() > 16 ||
            r.license.size() > 128 || r.source.size() > 1024 ||
            !std::set<std::string>{"low", "medium", "high"}.contains(r.confidence))
            throw std::runtime_error("invalid bounded rule metadata");
        for (const auto &fp : r.falsePositives)
            if (fp.size() > 1024)
                throw std::runtime_error("false positive guidance too long");
        for (const auto &s : r.eventSources)
            if (!std::set<std::string>{"process_etw", "sysmon", "windows_eventlog", "network", "registry",
                                       "file_monitor", "inventory", "artifact_enrichment", "yara", "baseline",
                                       "threat_intel"}
                     .contains(s))
                throw std::runtime_error("unknown event source " + s);
    }
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
        if (j.contains("event_type") || j.contains("all") || j.contains("any") || j.contains("condition"))
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
    if (v2 && j.contains("condition")) {
        if (j.contains("all") || j.contains("any"))
            throw std::runtime_error("condition and legacy predicates cannot be mixed");
        r.condition = j["condition"];
        int nodes = 0;
        validateCondition(r.condition, 0, nodes);
        return r;
    }
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
    const ProcessRecord *r = p && p->identity.processGuid
                                 ? t.resolveGuid(*p->identity.processGuid, e.timestampUtc)
                             : n && n->ownerProcessGuid ? t.resolveGuid(*n->ownerProcessGuid, e.timestampUtc)
                             : p ? t.resolve(p->identity.pid, e.timestampUtc, p->identity.creationTime100ns)
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
    if (f == "process.parent.name") {
        auto parent = r ? t.parent(*r) : nullptr;
        if (parent && parent->data.imagePath)
            return baseName(*parent->data.imagePath);
        if (p && p->parentImagePath)
            return baseName(*p->parentImagePath);
    }
    if (f == "process.parent.image_path") {
        auto parent = r ? t.parent(*r) : nullptr;
        if (parent && parent->data.imagePath)
            return parent->data.imagePath;
        if (p && p->parentImagePath)
            return p->parentImagePath;
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
            return r && ((n->ownerProcessGuid && r->data.identity.processGuid == n->ownerProcessGuid) ||
                         (n->ownerCreationTime100ns &&
                          r->data.identity.creationTime100ns == n->ownerCreationTime100ns))
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
    if (f == "event.source")
        return e.source;
    if (f == "event.attribution_confidence")
        return e.attributionConfidence;
    if (auto file = std::get_if<FilePayload>(&e.payload)) {
        if (f == "file.path")
            return file->path;
        if (f == "file.action")
            return file->action;
        if (f == "artifact.sha256" && file->metadata.contains("hash"))
            return file->metadata["hash"].value("sha256", std::string{});
        if (f == "artifact.signature.status" && file->metadata.contains("signature"))
            return file->metadata["signature"].value("status", std::string{});
    }
    if (auto i = std::get_if<InventoryPayload>(&e.payload)) {
        if (f == "inventory.key")
            return i->key;
        if (f == "inventory.action")
            return i->action;
        if (!i->after.is_null()) {
            auto image = i->after.value("image", i->after.value("target", std::string{}));
            if (f == "inventory.image")
                return image;
            if (f == "inventory.user_writable" && !image.empty())
                return userWritablePath(image) ? "true" : "false";
        }
    }
    if (auto o = std::get_if<ObservationPayload>(&e.payload)) {
        const std::map<std::string, std::string> aliases = {
            {"logon.result", "result"}, {"logon.type", "logon_type"},    {"dns.query", "query_name"},
            {"yara.rule", "rule"},      {"baseline.feature", "feature"}, {"ti.verdict", "verdict"}};
        if (auto it = aliases.find(f);
            it != aliases.end() && o->fields.contains(it->second) && o->fields[it->second].is_string())
            return o->fields[it->second].get<std::string>();
    }
    return {};
}
std::vector<Match> RuleEngine::evaluate(const SecurityEvent &e, const ProcessTracker &t) const {
    std::vector<Match> out;
    if (auto p = std::get_if<ProcessPayload>(&e.payload); p && p->initialEnumeration)
        return out;
    if (auto i = std::get_if<InventoryPayload>(&e.payload); i && i->initialSnapshot)
        return out;
    for (const auto &r : rules_) {
        auto compatibleType =
            e.type == EventType::SysmonNetworkConnect ? EventType::TcpConnectionObserved : e.type;
        if (!r.enabled || r.type != "event" ||
            (std::find(r.eventTypes.begin(), r.eventTypes.end(), e.type) == r.eventTypes.end() &&
             std::find(r.eventTypes.begin(), r.eventTypes.end(), compatibleType) == r.eventTypes.end()))
            continue;
        if (!r.eventSources.empty() &&
            std::find(r.eventSources.begin(), r.eventSources.end(), e.source) == r.eventSources.end())
            continue;
        if (!r.condition.is_null() && !condition(r.condition, e, t))
            continue;
        if (!std::all_of(r.all.begin(), r.all.end(), [&](const auto &p) { return predicate(p, e, t); }))
            continue;
        if (!r.any.empty() &&
            !std::any_of(r.any.begin(), r.any.end(), [&](const auto &p) { return predicate(p, e, t); }))
            continue;
        Match match{r.id,           r.description,  "",       r.score,     {e.id},
                    e.timestampUtc, e.timestampUtc, r.attack, r.confidence};
        match.attack = r.attack;
        match.confidence = r.confidence;
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
