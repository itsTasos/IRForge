#pragma once
#include "Rule.hpp"
namespace irforge {
struct Incident {
    std::string id, confidence = "high", status = "open";
    Millis first{}, last{};
    std::optional<ProcessIdentity> root;
    std::vector<ProcessIdentity> processes;
    std::vector<Match> matches;
    std::vector<std::string> notes;
    int score{};
};
int severityRank(const std::string &);
std::string severity(int);
void scoreIncident(Incident &);
Json incidentJson(const Incident &);
} // namespace irforge
