#pragma once
#include "irforge/core/Event.hpp"
#include <map>
namespace irforge {
struct ProcessRecord {
    ProcessPayload data;
    Millis start{}, lastSeen{};
    std::optional<Millis> end;
    EventId startEventId{};
};
class ProcessTracker {
    std::map<ProcessId, std::vector<ProcessRecord>> records_;
    std::uint64_t capacityEvictions_ = 0;

  public:
    void observe(const SecurityEvent &);
    const ProcessRecord *resolve(ProcessId, Millis, std::optional<std::uint64_t> creation = {}) const;
    const ProcessRecord *resolveGuid(const std::string &, Millis) const;
    const ProcessRecord *parent(const ProcessRecord &) const;
    const ProcessRecord *root(const ProcessRecord &) const;
    void prune(Millis cutoff, bool retainActive = false);
    std::size_t size() const;
    std::uint64_t capacityEvictions() const { return capacityEvictions_; }
};
} // namespace irforge
