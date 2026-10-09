#include "irforge/enrichment/ArtifactEnricher.hpp"
#include "irforge/detection/YaraScanner.hpp"
#include "irforge/enrichment/HashEngine.hpp"
#include <set>
namespace irforge {
ArtifactEnricher::ArtifactEnricher(EventBus &bus, const Config &config) : bus_(bus), config_(config) {
    for (int i = 0; i < config.scanner_workers; ++i)
        workers_.emplace_back([this](std::stop_token stop) {
            std::unique_ptr<YaraScanner> yara;
            if (config_.yara_enabled)
                try {
                    yara =
                        std::make_unique<YaraScanner>(config_.yara_rule_dir, config_.scanner_timeout_seconds,
                                                      config_.max_file_bytes, config_.yara_cpu_percent);
                } catch (const std::exception &error) {
                    SecurityEvent gap;
                    gap.schemaVersion = 2;
                    gap.type = EventType::CoverageGap;
                    gap.timestampUtc = utcNow();
                    gap.source = "yara";
                    gap.payload =
                        ObservationPayload{{{"reason", error.what()}, {"status", "initialization_failed"}}};
                    bus_.publish(std::move(gap));
                }
            std::map<std::string, std::pair<Json, Json>> cache;
            while (!stop.stop_requested()) {
                std::pair<std::string, std::string> work;
                {
                    std::unique_lock lock(mutex_);
                    ready_.wait(lock, stop, [&] { return !pending_.empty(); });
                    if (stop.stop_requested())
                        break;
                    work = std::move(pending_.front());
                    pending_.pop_front();
                }
                SecurityEvent e;
                e.type = EventType::ArtifactEnriched;
                e.timestampUtc = utcNow();
                e.source = "artifact_enrichment";
                e.schemaVersion = 2;
                e.attributionMethod = "unattributed_file_analysis";
                Json result;
                try {
                    if (!pathWithinRoot(work.first, work.second)) {
                        ++skipped_;
                        result = {{"status", "outside_root_or_unavailable"}};
                    } else {
                        auto stamp = fileIdentityMetadata(work.first);
                        auto found = cache.find(work.first);
                        if (found != cache.end() && found->second.first == stamp) {
                            result = found->second.second;
                            result["cache_hit"] = true;
                        } else {
                            result = artifactMetadata(work.first, config_.max_file_bytes,
                                                      config_.hash_enabled, config_.signature_enabled, stop,
                                                      config_.scanner_timeout_seconds);
                            if (yara)
                                result["yara"] = yara->scan(work.first, stop);
                            if (result.contains("yara") &&
                                result["yara"].value("status", std::string{}) == "complete" &&
                                result["hash"].value("status", std::string{}) == "complete" &&
                                result["yara"]["sha256"] != result["hash"]["sha256"])
                                result["association"] = "file changed between hash and YARA scans; each "
                                                        "result describes its own observed bytes";
                            if (result.value("hash", Json::object()).value("status", std::string{}) ==
                                "complete") {
                                if (cache.size() >= 1024)
                                    cache.erase(cache.begin());
                                cache[work.first] = {stamp, result};
                            }
                        }
                    }
                } catch (const std::exception &error) {
                    result = {{"status", "error"}, {"reason", error.what()}};
                }
                e.payload = FilePayload{work.first, "", "enriched", {}, result};
                if (result.contains("yara") && result["yara"].value("status", std::string{}) == "complete")
                    for (const auto &match : result["yara"]["matches"]) {
                        SecurityEvent y;
                        y.schemaVersion = 2;
                        y.type = EventType::YaraMatch;
                        y.timestampUtc = e.timestampUtc;
                        y.source = "yara";
                        y.attributionMethod = "local_pattern_match";
                        y.attributionConfidence = "high";
                        auto fields = match;
                        fields["file"] = work.first;
                        fields["sha256"] = result["yara"]["sha256"];
                        fields["pack"] = result["yara"]["pack"];
                        fields["scan_status"] = "complete";
                        fields["interpretation"] = "pattern match; not a malware verdict";
                        y.payload = ObservationPayload{fields};
                        if (!bus_.publish(std::move(y)))
                            ++skipped_;
                    }
                if (!bus_.publish(std::move(e)))
                    ++skipped_;
                else
                    ++completed_;
            }
        });
}
ArtifactEnricher::~ArtifactEnricher() { stop(); }
bool ArtifactEnricher::consider(const SecurityEvent &e) {
    auto file = std::get_if<FilePayload>(&e.payload);
    if (!file || (e.type != EventType::FileCreated && e.type != EventType::FileModified &&
                  e.type != EventType::FileRenamed))
        return false;
    static const std::set<std::string> extensions = {".exe", ".dll", ".sys", ".ps1", ".vbs", ".js",
                                                     ".bat", ".cmd", ".hta", ".zip", ".7z"};
    if (!extensions.contains(lower(filesystemPath(file->path).extension().string())))
        return false;
    std::string root;
    for (auto &configured : config_.file_roots) {
        auto expanded = expandWindowsPath(configured);
        if (pathWithinRoot(file->path, expanded)) {
            root = expanded;
            break;
        }
    }
    if (root.empty()) {
        ++skipped_;
        return false;
    }
    std::lock_guard lock(mutex_);
    if (pending_.size() >= config_.scanner_queue) {
        ++skipped_;
        return false;
    }
    if (std::any_of(pending_.begin(), pending_.end(), [&](auto &p) { return p.first == file->path; }))
        return true;
    pending_.emplace_back(file->path, root);
    ready_.notify_one();
    return true;
}
void ArtifactEnricher::stop() noexcept {
    for (auto &w : workers_)
        w.request_stop();
    ready_.notify_all();
    for (auto &w : workers_)
        if (w.joinable())
            w.join();
    workers_.clear();
}
Json ArtifactEnricher::health() const {
    std::lock_guard lock(mutex_);
    return {{"completed", completed_.load()},
            {"queue_depth", pending_.size()},
            {"skipped", skipped_.load()},
            {"workers", config_.scanner_workers},
            {"queue_limit", config_.scanner_queue}};
}
} // namespace irforge
