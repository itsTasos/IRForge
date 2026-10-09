#pragma once
#include "irforge/core/Event.hpp"
namespace irforge {
struct Predicate {
    std::string field, op;
    Json value;
};
struct Rule {
    std::string id, name, description, severity, type = "event", linkage;
    bool enabled = true;
    EventType eventType{};
    std::vector<EventType> eventTypes;
    std::vector<Predicate> all, any;
    std::vector<std::string> requiresRules;
    int score{}, windowSeconds = 60;
    Json condition = nullptr;
    std::vector<std::string> attack, eventSources, falsePositives;
    std::string license, source, confidence = "medium";
};
struct Match {
    std::string ruleId, reason, key;
    int points{};
    std::vector<EventId> eventIds;
    Millis first{}, last{};
    std::vector<std::string> attack;
    std::string confidence;
};
} // namespace irforge
