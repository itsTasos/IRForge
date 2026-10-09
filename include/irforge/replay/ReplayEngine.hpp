#pragma once
#include "irforge/detection/Correlator.hpp"
#include "irforge/output/AlertManager.hpp"
#include "irforge/output/Metrics.hpp"
#include <functional>
namespace irforge {
std::vector<SecurityEvent> readReplay(const std::string &);
struct ReplayCallbacks {
    std::function<void(const SecurityEvent &)> event;
    std::function<void(const std::vector<Incident> &)> incidents;
};
void replay(const std::string &, Correlator &, AlertManager &, JsonlWriter &, Metrics &, bool logAll,
            const ReplayCallbacks &callbacks = {});
} // namespace irforge
