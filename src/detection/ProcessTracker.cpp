#include "irforge/detection/ProcessTracker.hpp"
#include <algorithm>
#include <set>
namespace irforge {
void ProcessTracker::observe(const SecurityEvent &e) {
    auto p = std::get_if<ProcessPayload>(&e.payload);
    if (!p)
        return;
    if (e.type == EventType::ProcessStart) {
        auto &rows = records_[p->identity.pid];
        for (auto &r : rows)
            if ((p->identity.creationTime100ns &&
                 r.data.identity.creationTime100ns == p->identity.creationTime100ns) ||
                (p->identity.processGuid && r.data.identity.processGuid == p->identity.processGuid) ||
                (!p->identity.creationTime100ns && !r.data.identity.creationTime100ns &&
                 !p->identity.processGuid &&
                 r.data.identity.generation == (p->identity.generation ? p->identity.generation : e.id))) {
                r.lastSeen = std::max(r.lastSeen, e.timestampUtc);
                if (p->imagePath)
                    r.data.imagePath = p->imagePath;
                if (p->commandLine)
                    r.data.commandLine = p->commandLine;
                if (p->identity.processGuid)
                    r.data.identity.processGuid = p->identity.processGuid;
                if (p->identity.creationTime100ns)
                    r.data.identity.creationTime100ns = p->identity.creationTime100ns;
                if (p->parentProcessGuid)
                    r.data.parentProcessGuid = p->parentProcessGuid;
                if (p->parentImagePath)
                    r.data.parentImagePath = p->parentImagePath;
                return;
            }
        ProcessRecord r{*p, e.timestampUtc, e.timestampUtc, {}};
        r.startEventId = e.id;
        if (!r.data.identity.creationTime100ns)
            r.data.identity.generation = p->identity.generation ? p->identity.generation : e.id;
        rows.push_back(r);
        std::sort(rows.begin(), rows.end(), [](const auto &a, const auto &b) { return a.start < b.start; });
        for (std::size_t index = 1; index < rows.size(); ++index)
            if (!rows[index - 1].end || *rows[index - 1].end >= rows[index].start)
                rows[index - 1].end = rows[index].start - 1;
        if (size() > 20000) {
            auto oldest = records_.begin();
            for (auto it = records_.begin(); it != records_.end(); ++it)
                if (it->second.front().lastSeen < oldest->second.front().lastSeen)
                    oldest = it;
            oldest->second.erase(oldest->second.begin());
            if (oldest->second.empty())
                records_.erase(oldest);
            ++capacityEvictions_;
        }
    } else if (e.type == EventType::ProcessExit) {
        auto row = p->identity.processGuid
                       ? resolveGuid(*p->identity.processGuid, e.timestampUtc)
                       : resolve(p->identity.pid, e.timestampUtc, p->identity.creationTime100ns);
        if (row) {
            auto &r = const_cast<ProcessRecord &>(*row);
            r.end = e.timestampUtc;
            r.lastSeen = e.timestampUtc;
        }
    }
}
const ProcessRecord *ProcessTracker::resolveGuid(const std::string &guid, Millis t) const {
    for (const auto &[pid, rows] : records_) {
        (void)pid;
        for (const auto &r : rows)
            if (r.data.identity.processGuid && lower(*r.data.identity.processGuid) == lower(guid) &&
                r.start <= t && (!r.end || *r.end >= t))
                return &r;
    }
    return nullptr;
}
const ProcessRecord *ProcessTracker::resolve(ProcessId pid, Millis t,
                                             std::optional<std::uint64_t> creation) const {
    auto it = records_.find(pid);
    if (it == records_.end())
        return nullptr;
    const ProcessRecord *result = nullptr;
    for (const auto &r : it->second) {
        if (r.start > t)
            break;
        // A later generation invalidates an older PID even when the old exit was lost.
        result = &r;
    }
    if (!result || (result->end && *result->end < t) ||
        (creation && result->data.identity.creationTime100ns != creation))
        return nullptr;
    return result;
}
const ProcessRecord *ProcessTracker::parent(const ProcessRecord &r) const {
    if (r.data.parentProcessGuid && r.data.identity.processGuid)
        return resolveGuid(*r.data.parentProcessGuid, r.start);
    if (!r.data.parentPid || r.data.initialEnumeration)
        return nullptr;
    auto p = resolve(*r.data.parentPid, r.start);
    if (!p || !p->data.identity.creationTime100ns || !r.data.identity.creationTime100ns ||
        *p->data.identity.creationTime100ns > *r.data.identity.creationTime100ns || p == &r)
        return nullptr;
    return p;
}
const ProcessRecord *ProcessTracker::root(const ProcessRecord &r) const {
    auto p = &r;
    std::set<std::string> seen;
    for (int n = 0; n < 32; ++n) {
        if (!seen.insert(identityKey(p->data.identity)).second)
            break;
        auto next = parent(*p);
        if (!next)
            break;
        p = next;
    }
    return p;
}
void ProcessTracker::prune(Millis cutoff, bool retainActive) {
    for (auto it = records_.begin(); it != records_.end();) {
        auto &rows = it->second;
        std::erase_if(rows, [&](const auto &r) {
            return retainActive ? (r.end && *r.end < cutoff) : r.lastSeen < cutoff;
        });
        if (rows.empty())
            it = records_.erase(it);
        else
            ++it;
    }
}
std::size_t ProcessTracker::size() const {
    std::size_t n = 0;
    for (const auto &[pid, rows] : records_) {
        (void)pid;
        n += rows.size();
    }
    return n;
}
} // namespace irforge
