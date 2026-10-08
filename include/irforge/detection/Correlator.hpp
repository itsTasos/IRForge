#pragma once
#include "RiskEngine.hpp"
#include "RuleEngine.hpp"
#include "irforge/core/Config.hpp"
#include <deque>
#include <map>
namespace irforge {
class Correlator {
    RuleEngine rules_;
    Config config_;
    std::deque<SecurityEvent> history_;
    Millis watermark_{};
    std::uint64_t evicted_{};
    std::map<std::string, Incident> incidents_;
    std::vector<Incident> rebuild();

  public:
    Correlator(RuleEngine r, Config c) : rules_(std::move(r)), config_(std::move(c)) {}
    std::vector<Incident> ingest(const SecurityEvent &);
    std::vector<Incident> expire(Millis now);
    const std::map<std::string, Incident> &incidents() const { return incidents_; }
    std::uint64_t evicted() const { return evicted_; }
};
} // namespace irforge
