#pragma once
#include "irforge/detection/Correlator.hpp"
#include "irforge/output/AlertManager.hpp"
#include "irforge/output/Metrics.hpp"
namespace irforge {
std::vector<SecurityEvent> readReplay(const std::string &);
void replay(const std::string &, Correlator &, AlertManager &, JsonlWriter &, Metrics &, bool logAll);
} // namespace irforge
