#include "irforge/ti/TiEnricher.hpp"
namespace irforge {
TiEnricher::TiEnricher(StoreWorker &s, EventBus &b, const Config &c) : store_(s), bus_(b), config_(c) {
    worker_ = std::jthread([this](std::stop_token stop) {
        VirusTotalClient client(store_);
        while (!stop.stop_requested()) {
            Json job;
            {
                std::unique_lock lock(mutex_);
                ready_.wait(lock, stop, [&] { return !queue_.empty(); });
                if (stop.stop_requested())
                    break;
                job = queue_.front();
                queue_.pop_front();
            }
            Json fields;
            try {
                auto feed = store_.call({{"op", "get"}, {"table", "settings"}, {"key", "ti/local-ioc-feed"}});
                fields = {{"kind", job["kind"]},
                          {"indicator", job["indicator"]},
                          {"observed_event_id", job["event_id"]},
                          {"local_matches", feed.is_null()
                                                ? Json::array()
                                                : IocMatcher(feed).match(job["kind"], job["indicator"])},
                          {"verdict", "unknown"}};
                if (!fields["local_matches"].empty())
                    fields["verdict"] = "local_ioc_match";
                if (config_.threat_intel_enabled &&
                    (job["kind"] == "sha256" ||
                     VirusTotalClient::publicIp(job["indicator"].get<std::string>()))) {
                    auto ti = config_.platform.value("threat_intel", Json::object());
                    auto result =
                        client.lookup(job["kind"], job["indicator"], true,
                                      ti.value("credential_target", std::string("IRForge.VirusTotal.v1")));
                    fields["virustotal"] = result;
                    if (fields["verdict"] == "unknown")
                        fields["verdict"] = result.value("verdict", std::string("unknown"));
                }
            } catch (const std::exception &e) {
                if (!fields.is_null()) {
                    fields["online_error"] = {{"status", "unavailable"}, {"reason", e.what()}};
                } else {
                    fields = {{"kind", job["kind"]},
                              {"indicator", job["indicator"]},
                              {"observed_event_id", job["event_id"]},
                              {"status", "unavailable"},
                              {"reason", e.what()},
                              {"verdict", "unknown"}};
                }
            }
            SecurityEvent event;
            event.schemaVersion = 2;
            event.type = EventType::ThreatIntelResult;
            event.source = "threat_intel";
            event.timestampUtc = utcNow();
            event.attributionMethod = "indicator_reputation";
            event.attributionConfidence = "low";
            fields["file_uploaded"] = false;
            event.payload = ObservationPayload{fields};
            if (!bus_.publish(std::move(event)))
                ++skipped_;
        }
    });
}
TiEnricher::~TiEnricher() { stop(); }
Json TiEnricher::health() const {
    std::lock_guard lock(mutex_);
    return {{"queue_depth", queue_.size()}, {"queue_limit", 100}, {"skipped", skipped_.load()}};
}
bool TiEnricher::consider(const SecurityEvent &e) {
    Json job;
    if (auto f = std::get_if<FilePayload>(&e.payload);
        f && e.type == EventType::ArtifactEnriched && f->metadata.contains("hash") &&
        f->metadata["hash"].value("status", std::string{}) == "complete")
        job = {{"kind", "sha256"}, {"indicator", f->metadata["hash"].at("sha256")}, {"event_id", e.uniqueId}};
    if (auto n = std::get_if<TcpPayload>(&e.payload);
        n && !n->firstSnapshot && addressClass(n->remoteAddress) != "invalid")
        job = {{"kind", "ip"}, {"indicator", n->remoteAddress}, {"event_id", e.uniqueId}};
    if (job.is_null())
        return false;
    std::lock_guard lock(mutex_);
    if (queue_.size() >= 100) {
        ++skipped_;
        return false;
    }
    for (const auto &row : queue_)
        if (row["kind"] == job["kind"] && row["indicator"] == job["indicator"])
            return true;
    queue_.push_back(job);
    ready_.notify_one();
    return true;
}
void TiEnricher::stop() noexcept {
    if (worker_.joinable()) {
        worker_.request_stop();
        ready_.notify_all();
        worker_.join();
    }
}
} // namespace irforge
