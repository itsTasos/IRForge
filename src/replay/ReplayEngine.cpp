#include "irforge/replay/ReplayEngine.hpp"
#include "irforge/core/Clock.hpp"
#include <fstream>
#include <set>
#include <stdexcept>
namespace irforge {
std::vector<SecurityEvent> readReplay(const std::string &path) {
    std::ifstream f(filesystemPath(path), std::ios::binary);
    if (!f)
        throw std::runtime_error("cannot open replay " + path);
    std::vector<SecurityEvent> events;
    std::set<EventId> ids;
    std::string line;
    std::size_t lineNo = 0, total = 0;
    // Read a bounded line without allocating an unbounded attacker-controlled string.
    while (f.peek() != EOF) {
        line.clear();
        char c;
        while (f.get(c) && c != '\n') {
            if (line.size() >= 1048576)
                throw std::runtime_error(path + ": line exceeds 1 MiB");
            line += c;
        }
        ++lineNo;
        total += line.size();
        if (events.size() >= 100000 || total > 64 * 1024 * 1024)
            throw std::runtime_error("replay exceeds 100k events / 64 MiB");
        if (line.empty())
            continue;
        try {
            auto e = Json::parse(line, [](int depth, Json::parse_event_t, Json &) {
                         if (depth > 32)
                             throw std::runtime_error("JSON nesting exceeds 32 levels");
                         return true;
                     }).get<SecurityEvent>();
            if (!e.id || !ids.insert(e.id).second)
                throw std::runtime_error("event_id must be positive and unique");
            events.push_back(std::move(e));
        } catch (const std::exception &ex) {
            throw std::runtime_error(path + ":" + std::to_string(lineNo) + ": " + ex.what());
        }
    }
    if (f.bad())
        throw std::runtime_error("replay read failed");
    return events;
}
void replay(const std::string &path, Correlator &correlator, AlertManager &alerts, JsonlWriter &writer,
            Metrics &metrics, bool logAll) {
    auto events = readReplay(path);
    VirtualClock clock;
    if (!events.empty())
        metrics.start = events.front().timestampUtc;
    for (const auto &e : events) {
        clock.advance(e.timestampUtc);
        metrics.observe(e);
        if (logAll)
            writer.event(e);
        alerts.update(correlator.ingest(e), clock.now());
    }
    writer.document("monitor-health.json",
                    metrics.json(clock.now(), 0, correlator.incidents().size(), correlator.evicted()));
    writer.flush();
}
} // namespace irforge
