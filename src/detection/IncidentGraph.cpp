#include "irforge/detection/IncidentGraph.hpp"
#include <map>
#include <set>
namespace irforge {
Json incidentGraph(const Json &timeline) {
    if (!timeline.is_array() || timeline.size() > 20000)
        throw std::runtime_error("incident graph timeline bounds");
    std::vector<SecurityEvent> events;
    for (const auto &j : timeline)
        events.push_back(j.get<SecurityEvent>());
    std::sort(events.begin(), events.end(),
              [](const auto &a, const auto &b) { return a.timestampUtc < b.timestampUtc; });
    ProcessTracker tracker;
    std::string host;
    for (const auto &e : events) {
        if (host.empty())
            host = e.hostId;
        if (e.hostId != host)
            throw std::runtime_error("incident graph cannot mix hosts");
        tracker.observe(e);
    }
    Json nodes = Json::array(), edges = Json::array();
    std::set<std::string> nodeKeys, edgeKeys;
    std::size_t omittedNodes = 0, omittedEdges = 0;
    auto node = [&](const std::string &id, const std::string &kind, const std::string &label,
                    const Json &data) {
        if (!nodeKeys.contains(id) && nodes.size() >= 512) {
            ++omittedNodes;
            return;
        }
        if (nodeKeys.insert(id).second)
            nodes.push_back({{"id", id}, {"kind", kind}, {"label", label}, {"data", data}});
    };
    auto edge = [&](const std::string &from, const std::string &to, const std::string &type,
                    const std::string &confidence, const SecurityEvent &e, const std::string &reason) {
        auto key = from + "|" + to + "|" + type + "|" + e.uniqueId;
        if (!nodeKeys.contains(from) || !nodeKeys.contains(to) || edges.size() >= 1024) {
            ++omittedEdges;
            return;
        }
        if (edgeKeys.insert(key).second)
            edges.push_back({{"from", from},
                             {"to", to},
                             {"type", type},
                             {"confidence", confidence},
                             {"evidence_event_id", e.uniqueId},
                             {"timestamp_utc", formatUtc(e.timestampUtc)},
                             {"reason", reason}});
    };
    auto processNode = [&](const ProcessRecord &p) {
        auto id = host + "/process/" + identityKey(p.data.identity);
        node(id, "process",
             p.data.imagePath ? baseName(*p.data.imagePath) : "PID " + std::to_string(p.data.identity.pid),
             {{"identity", identityJson(p.data.identity)},
              {"image", p.data.imagePath ? Json(*p.data.imagePath) : Json(nullptr)}});
        return id;
    };
    for (const auto &e : events) {
        auto eventId = e.uniqueId.empty() ? host + "/event/" + std::to_string(e.id) : e.uniqueId;
        node(eventId, "event", eventTypeName(e.type),
             {{"source", e.source},
              {"timestamp_utc", formatUtc(e.timestampUtc)},
              {"attribution", e.attributionMethod}});
        if (auto p = std::get_if<ProcessPayload>(&e.payload)) {
            auto record =
                p->identity.processGuid
                    ? tracker.resolveGuid(*p->identity.processGuid, e.timestampUtc)
                    : tracker.resolve(p->identity.pid, e.timestampUtc, p->identity.creationTime100ns);
            if (record) {
                auto child = processNode(*record);
                edge(eventId, child, "observed_process", e.attributionConfidence, e,
                     "Provider process observation");
                if (auto parent = tracker.parent(*record)) {
                    auto from = processNode(*parent);
                    edge(from, child, "process_parent", p->parentProcessGuid ? "high" : "medium", e,
                         p->parentProcessGuid ? "Explicit provider parent GUID"
                                              : "Verified lifetime and creation-time parent PID");
                }
            }
        }
        if (auto n = std::get_if<TcpPayload>(&e.payload)) {
            auto socket = host + "/network/" + n->remoteAddress + ":" + std::to_string(n->remotePort);
            node(socket, "network", n->remoteAddress + ":" + std::to_string(n->remotePort),
                 {{"protocol", n->protocol}, {"direction", "unknown unless explicit provider metadata"}});
            edge(eventId, socket, "observed_endpoint", "high", e,
                 "Endpoint observed; TCP snapshot does not establish direction");
            auto owner = n->ownerProcessGuid ? tracker.resolveGuid(*n->ownerProcessGuid, e.timestampUtc)
                         : n->ownerCreationTime100ns
                             ? tracker.resolve(n->ownerPid, e.timestampUtc, n->ownerCreationTime100ns)
                             : nullptr;
            if (owner)
                edge(processNode(*owner), socket, "process_network", n->ownerProcessGuid ? "high" : "medium",
                     e, "Explicit GUID or verified owner creation time");
        }
        if (auto f = std::get_if<FilePayload>(&e.payload)) {
            auto file = host + "/file/" + normalizePath(f->path);
            node(file, "file", f->path, {{"metadata", f->metadata}});
            edge(eventId, file, "observed_artifact", "high", e, "Path observation, not writer attribution");
            if (f->metadata.contains("provider_process_guid") &&
                f->metadata["provider_process_guid"].is_string())
                if (auto p = tracker.resolveGuid(f->metadata["provider_process_guid"].get<std::string>(),
                                                 e.timestampUtc))
                    edge(processNode(*p), file, "process_file", "high", e,
                         "Explicit Sysmon file-create process GUID");
        }
        if (auto r = std::get_if<RegistryPayload>(&e.payload)) {
            auto key = host + "/registry/" + lower(r->hive + "\\" + r->keyPath + "\\" + r->valueName);
            node(key, "registry", r->hive + "\\" + r->keyPath + "\\" + r->valueName,
                 {{"actor_pid", r->actorPid ? Json(*r->actorPid) : Json(nullptr)},
                  {"writer", r->actorPid ? "provider_explicit_pid_only" : "unknown"}});
            edge(eventId, key, "persistence_observation", r->actorPid ? "medium" : "low", e,
                 r->actorPid ? "Provider reports actor PID; generation not inferred"
                             : "Native diff has no writer identity");
        }
        if (auto i = std::get_if<InventoryPayload>(&e.payload)) {
            auto id = host + "/persistence/" + i->kind + "/" + lower(i->key);
            node(id, "persistence", i->kind + ": " + i->key,
                 {{"initial_snapshot", i->initialSnapshot}, {"after", i->after}});
            edge(eventId, id, "persistence_observation", "high", e,
                 "Configuration observation; creating process unknown");
        }
        if (auto o = std::get_if<ObservationPayload>(&e.payload); o && e.type == EventType::YaraMatch) {
            auto rule = o->fields.value("rule", std::string("unknown"));
            auto id = "yara/" + rule;
            node(id, "rule", rule, {{"interpretation", "pattern match, not malware verdict"}});
            edge(eventId, id, "pattern_match", "high", e, "Official YARA-X rule match");
        }
    }
    return {
        {"nodes", nodes},
        {"edges", edges},
        {"truncated", omittedNodes != 0 || omittedEdges != 0},
        {"omitted_node_observations", omittedNodes},
        {"omitted_edge_observations", omittedEdges},
        {"interpretation", "Evidence relationships carry explicit confidence; adjacency is not causation"}};
}
} // namespace irforge
