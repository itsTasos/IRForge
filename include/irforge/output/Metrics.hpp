#pragma once
#include "irforge/core/Event.hpp"
#include <map>
namespace irforge {
struct Metrics {
    std::map<std::string, std::uint64_t> received;
    std::map<std::string, std::uint64_t> sourceErrors;
    std::map<std::string, StatusPayload> sources;
    Millis start{};
    void observe(const SecurityEvent &);
    Json json(Millis now, std::uint64_t drops, std::size_t incidents, std::uint64_t evicted) const;
};
} // namespace irforge
