#include "irforge/detection/Correlator.hpp"
#include <algorithm>
#include <set>
namespace irforge {
namespace {
bool office(const ProcessRecord *p) {
    return p && p->data.imagePath &&
           std::set<std::string>{"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}.contains(
               baseName(*p->data.imagePath));
}
const ProcessRecord *chainRoot(const ProcessRecord *p, const ProcessTracker &t) {
    if (!p)
        return p;
    auto cur = p;
    for (int n = 0; n < 32; ++n) {
        if (office(cur))
            return cur;
        auto parent = t.parent(*cur);
        if (!parent)
            break;
        cur = parent;
    }
    return p;
}
struct Evidence {
    Match match;
    const SecurityEvent *event;
    const ProcessRecord *process;
    std::string group;
};
std::string artifact(const RegistryPayload &r) {
    return lower(r.hive + "\\" + r.keyPath + "\\" + r.valueName + "@" + r.view);
}
} // namespace
std::vector<Incident> Correlator::ingest(const SecurityEvent &e) {
    watermark_ = std::max(watermark_, e.timestampUtc);
    if (e.type != EventType::MonitorStatus)
        history_.push_back(e);
    return expire(watermark_);
}
std::vector<Incident> Correlator::expire(Millis now) {
    watermark_ = std::max(watermark_, now);
    auto cutoff = watermark_ - config_.context_retention_seconds * 1000LL;
    std::erase_if(history_, [&](const auto &e) { return e.timestampUtc < cutoff; });
    while (history_.size() > config_.max_history_events) {
        history_.pop_front();
        ++evicted_;
    }
    return rebuild();
}
std::vector<Incident> Correlator::rebuild() {
    std::vector<const SecurityEvent *> ordered;
    for (const auto &e : history_)
        ordered.push_back(&e);
    std::sort(ordered.begin(), ordered.end(), [](auto a, auto b) {
        return a->timestampUtc == b->timestampUtc ? a->id < b->id : a->timestampUtc < b->timestampUtc;
    });
    ProcessTracker tracker;
    for (auto e : ordered)
        tracker.observe(*e);
    std::vector<Evidence> evidence;
    auto activeCutoff = watermark_ - config_.correlation_window_seconds * 1000LL;
    for (auto e : ordered) {
        if (e->timestampUtc < activeCutoff)
            continue;
        const ProcessRecord *p = nullptr;
        if (auto x = std::get_if<ProcessPayload>(&e->payload))
            p = tracker.resolve(x->identity.pid, e->timestampUtc, x->identity.creationTime100ns);
        if (auto x = std::get_if<TcpPayload>(&e->payload))
            p = tracker.resolve(x->ownerPid, e->timestampUtc, x->ownerCreationTime100ns);
        auto root = chainRoot(p, tracker);
        auto group = root ? "process/" + identityKey(root->data.identity) : "event/" + std::to_string(e->id);
        if (auto x = std::get_if<RegistryPayload>(&e->payload))
            group = "registry/" + artifact(*x);
        for (auto m : rules_.evaluate(*e, tracker)) {
            m.key = m.ruleId + "/" + (p ? identityKey(p->data.identity) : group);
            evidence.push_back({std::move(m), e, p, group});
        }
    }
    // Link only identical explicit executable paths, and only to an already suspicious lineage.
    // Registry writer PID remains unknown regardless of a path match.
    std::set<std::string> weakGroups;
    for (auto &item : evidence) {
        auto reg = std::get_if<RegistryPayload>(&item.event->payload);
        if (!reg || !reg->newData || !reg->newData->text)
            continue;
        if (RuleEngine::field("registry.is_run", *item.event, tracker) != std::optional<std::string>("true"))
            continue;
        auto path = executablePath(*reg->newData->text);
        if (!path)
            continue;
        std::set<std::string> candidates;
        for (const auto &suspicious : evidence) {
            if (suspicious.match.ruleId != "PROC-001" || !suspicious.process)
                continue;
            if (std::abs(item.event->timestampUtc - suspicious.event->timestampUtc) >
                config_.correlation_window_seconds * 1000LL)
                continue;
            for (auto pe : ordered) {
                auto pp = std::get_if<ProcessPayload>(&pe->payload);
                if (!pp || !pp->imagePath || normalizePath(*pp->imagePath) != *path)
                    continue;
                auto record =
                    tracker.resolve(pp->identity.pid, pe->timestampUtc, pp->identity.creationTime100ns);
                auto root = chainRoot(record, tracker);
                if (root && "process/" + identityKey(root->data.identity) == suspicious.group)
                    candidates.insert(suspicious.group);
            }
        }
        if (candidates.size() == 1) {
            item.group = *candidates.begin();
            weakGroups.insert(item.group);
        }
    }
    std::map<std::string, Incident> current;
    for (const auto &item : evidence) {
        auto &i = current[item.group];
        if (i.id.empty()) {
            i.id = item.group;
            i.first = item.match.first;
            i.last = item.match.last;
        }
        i.first = std::min(i.first, item.match.first);
        i.last = std::max(i.last, item.match.last);
        if (item.process) {
            auto root = chainRoot(item.process, tracker);
            i.root = root->data.identity;
            if (std::find(i.processes.begin(), i.processes.end(), root->data.identity) == i.processes.end())
                i.processes.push_back(root->data.identity);
            if (std::find(i.processes.begin(), i.processes.end(), item.process->data.identity) ==
                i.processes.end())
                i.processes.push_back(item.process->data.identity);
            if (!item.process->data.identity.creationTime100ns)
                i.confidence = "low";
        }
        if (std::holds_alternative<TcpPayload>(item.event->payload) &&
            RuleEngine::field("network.owner_verified", *item.event, tracker) !=
                std::optional<std::string>("true"))
            i.confidence = "low";
        if (std::holds_alternative<RegistryPayload>(item.event->payload)) {
            i.confidence = "low";
            i.notes = {
                "Registry writer is unknown (actor_pid=null); temporal proximity is not writer attribution."};
        }
        auto existing = std::find_if(i.matches.begin(), i.matches.end(),
                                     [&](const auto &m) { return m.ruleId == item.match.ruleId; });
        if (existing == i.matches.end())
            i.matches.push_back(item.match);
        else {
            existing->eventIds.insert(existing->eventIds.end(), item.match.eventIds.begin(),
                                      item.match.eventIds.end());
            existing->last = std::max(existing->last, item.match.last);
        }
    }
    for (auto &[key, i] : current) {
        if (weakGroups.contains(key))
            i.notes.push_back("Related artifact: identical normalized executable path in a suspicious "
                              "lineage; this does not prove the process wrote the Registry.");
        for (const auto &rule : rules_.rules()) {
            if (rule.type != "correlation" || !rule.enabled)
                continue;
            // Search a complete window around each observation, so an earlier unrelated match cannot mask a
            // later valid chain.
            bool matched = false;
            std::vector<EventId> ids;
            Millis first{}, last{};
            for (const auto &anchor : evidence) {
                if (anchor.group != key)
                    continue;
                std::vector<const Evidence *> chosen;
                for (const auto &required : rule.requiresRules) {
                    auto found = std::find_if(evidence.begin(), evidence.end(), [&](const auto &v) {
                        if (v.group != key || v.match.ruleId != required ||
                            v.event->timestampUtc < anchor.event->timestampUtc ||
                            v.event->timestampUtc > anchor.event->timestampUtc + rule.windowSeconds * 1000LL)
                            return false;
                        if (rule.linkage == "same_process") {
                            if (!v.process || !anchor.process ||
                                v.process->data.identity != anchor.process->data.identity)
                                return false;
                            if (std::holds_alternative<TcpPayload>(v.event->payload) &&
                                RuleEngine::field("network.owner_verified", *v.event, tracker) !=
                                    std::optional<std::string>("true"))
                                return false;
                        }
                        return true;
                    });
                    if (found == evidence.end())
                        break;
                    chosen.push_back(&*found);
                }
                if (chosen.size() == rule.requiresRules.size() &&
                    (rule.linkage != "lineage_path" || weakGroups.contains(key))) {
                    first = chosen.front()->event->timestampUtc;
                    last = first;
                    for (auto v : chosen) {
                        ids.insert(ids.end(), v->match.eventIds.begin(), v->match.eventIds.end());
                        first = std::min(first, v->event->timestampUtc);
                        last = std::max(last, v->event->timestampUtc);
                    }
                    matched = true;
                    break;
                }
            }
            if (matched)
                i.matches.push_back(
                    {rule.id, rule.description, rule.id + "/" + key, rule.score, ids, first, last});
        }
        scoreIncident(i);
    }
    std::vector<Incident> updates;
    for (auto &[key, i] : current) {
        auto old = incidents_.find(key);
        if (old == incidents_.end() || old->second.score != i.score ||
            old->second.matches.size() != i.matches.size())
            updates.push_back(i);
    }
    for (const auto &[key, old] : incidents_)
        if (!current.contains(key)) {
            auto expired = old;
            expired.status = "expired";
            expired.score = 0;
            updates.push_back(expired);
        }
    incidents_ = std::move(current);
    return updates;
}
} // namespace irforge
