#include "irforge/detection/RiskEngine.hpp"
#include <algorithm>
#include <set>
#include <stdexcept>
namespace irforge {
int severityRank(const std::string &s) {
    const std::vector<std::string> names = {"informational", "low", "medium", "high", "critical"};
    auto it = std::find(names.begin(), names.end(), s);
    if (it == names.end())
        throw std::runtime_error("invalid severity " + s);
    return static_cast<int>(it - names.begin());
}
std::string severity(int s) {
    return s >= 80 ? "critical" : s >= 60 ? "high" : s >= 40 ? "medium" : s >= 20 ? "low" : "informational";
}
void scoreIncident(Incident &i) {
    int s = 0;
    std::set<std::string> seen;
    for (const auto &m : i.matches)
        if (seen.insert(m.ruleId).second)
            s += m.points;
    i.score = std::clamp(s, 0, 100);
}
Json incidentJson(const Incident &i) {
    Json rules = Json::array(), ids = Json::array(), processes = Json::array();
    std::set<EventId> evidence;
    for (const auto &m : i.matches) {
        rules.push_back({{"rule_id", m.ruleId},
                         {"points", m.points},
                         {"reason", m.reason},
                         {"evidence_key", m.key},
                         {"event_ids", m.eventIds}});
        evidence.insert(m.eventIds.begin(), m.eventIds.end());
    }
    for (auto id : evidence)
        ids.push_back(id);
    for (const auto &p : i.processes)
        processes.push_back(identityJson(p));
    return {{"incident_id", i.id},
            {"first_seen_utc", formatUtc(i.first)},
            {"last_seen_utc", formatUtc(i.last)},
            {"root_process_identity", i.root ? identityJson(*i.root) : Json(nullptr)},
            {"linked_process_identities", processes},
            {"event_ids", ids},
            {"matched_rules", rules},
            {"score", i.score},
            {"severity", severity(i.score)},
            {"confidence", i.confidence},
            {"attribution_notes", i.notes},
            {"status", i.status}};
}
} // namespace irforge
