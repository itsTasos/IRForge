#include "irforge/output/Metrics.hpp"
namespace irforge {
void Metrics::observe(const SecurityEvent &e) {
    ++received[e.source];
    if (auto s = std::get_if<StatusPayload>(&e.payload)) {
        sources[e.source] = *s;
        if (s->state == "degraded")
            ++sourceErrors[e.source];
    }
}
Json Metrics::json(Millis now, std::uint64_t drops, std::size_t incidents, std::uint64_t evicted) const {
    Json source = Json::object();
    bool degraded = drops > 0 || evicted > 0;
    for (const auto &[name, s] : sources) {
        source[name] = {{"state", s.state},
                        {"message", s.message},
                        {"error_code", s.errorCode},
                        {"events_lost", s.eventsLost},
                        {"buffers_lost", s.buffersLost},
                        {"decode_errors", s.decodeErrors}};
        if (s.state == "degraded" || s.state == "disabled" || s.state == "starting" || s.eventsLost ||
            s.buffersLost || s.decodeErrors)
            degraded = true;
    }
    return {{"schema_version", 1},
            {"timestamp_utc", formatUtc(now)},
            {"uptime_ms", now - start},
            {"coverage", degraded ? "DEGRADED" : "active"},
            {"sources", source},
            {"events_received_by_source", received},
            {"source_error_counts", sourceErrors},
            {"queue_drops", drops},
            {"context_evictions", evicted},
            {"active_incidents", incidents}};
}
} // namespace irforge
