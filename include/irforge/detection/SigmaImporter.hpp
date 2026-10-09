#pragma once
#include "irforge/detection/RuleEngine.hpp"
namespace irforge {
// Deliberately restricted Windows process_creation subset. Unsupported syntax
// fails before any output is committed; this is not a full Sigma implementation.
Json importSigma(const std::string &yaml, const std::string &origin);
Json testRules(const RuleEngine &, const std::vector<SecurityEvent> &);
} // namespace irforge
