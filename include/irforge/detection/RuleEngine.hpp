#pragma once
#include "ProcessTracker.hpp"
#include "Rule.hpp"
namespace irforge {
class RuleEngine {
    std::vector<Rule> rules_;

  public:
    static RuleEngine load(const std::string &);
    static Rule parse(const Json &);
    explicit RuleEngine(std::vector<Rule> r = {}) : rules_(std::move(r)) {}
    const std::vector<Rule> &rules() const { return rules_; }
    std::vector<Match> evaluate(const SecurityEvent &, const ProcessTracker &) const;
    static std::optional<std::string> field(const std::string &, const SecurityEvent &,
                                            const ProcessTracker &);
};
} // namespace irforge
