#pragma once
#include "JsonlWriter.hpp"
#include "irforge/detection/RiskEngine.hpp"
#include <map>
namespace irforge {
class AlertManager {
    JsonlWriter &writer_;
    int minimum_;
    bool quiet_;
    std::map<std::string, std::pair<int, Millis>> emitted_;
    std::uint64_t sequence_{};

  public:
    AlertManager(JsonlWriter &w, const std::string &min, bool quiet)
        : writer_(w), minimum_(severityRank(min)), quiet_(quiet) {}
    void update(const std::vector<Incident> &, Millis);
    std::uint64_t count() const { return sequence_; }
};
} // namespace irforge
