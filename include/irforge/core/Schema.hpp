#pragma once
#include "Event.hpp"
#include "irforge/detection/RiskEngine.hpp"
namespace irforge {
std::string newUuid();
std::string stableHostId();
Json upgradeEvent(const Json &, const std::string &host, const std::string &session);
Json incidentV2(const Incident &, const std::string &host, const std::string &session);
std::string observationDedupKey(const SecurityEvent &);
void validateDocument(const Json &, std::size_t maxBytes = 1048576);
} // namespace irforge
