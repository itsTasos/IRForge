#include "irforge/output/AlertManager.hpp"
#include <iostream>
namespace irforge {
void AlertManager::update(const std::vector<Incident> &incidents, Millis now) {
    for (auto it = emitted_.begin(); it != emitted_.end();) {
        if (now - it->second.second > 86400000)
            it = emitted_.erase(it);
        else
            ++it;
    }
    for (const auto &i : incidents) {
        if (i.status == "expired") {
            emitted_.erase(i.id);
            continue;
        }
        int rank = severityRank(severity(i.score));
        if (rank < minimum_)
            continue;
        auto it = emitted_.find(i.id);
        if (it != emitted_.end() && rank <= it->second.first)
            continue;
        emitted_[i.id] = {rank, now};
        auto j = incidentJson(i);
        j["schema_version"] = 1;
        j["alert_id"] = "alert-" + std::to_string(++sequence_);
        j["timestamp_utc"] = formatUtc(now);
        j["title"] = "Observed endpoint behavior requires triage";
        j["rule_ids"] = Json::array();
        std::string explanation;
        for (const auto &m : i.matches) {
            j["rule_ids"].push_back(m.ruleId);
            if (!explanation.empty())
                explanation += ' ';
            explanation += m.reason;
        }
        j["evidence_event_ids"] = j["event_ids"];
        j["explanation"] = explanation;
        j["limitations"] = {"Risk score is a triage heuristic, not malware probability.",
                            "TCP snapshot polling may miss short-lived sockets; a row does not establish "
                            "connection direction.",
                            "Registry notifications do not identify the writer PID."};
        writer_.alert(j);
        if (!quiet_)
            std::cout << "ALERT " << severity(i.score) << " score=" << i.score
                      << " confidence=" << i.confidence << " " << i.id << " " << explanation << '\n';
    }
}
} // namespace irforge
