#include "irforge/detection/BaselineEngine.hpp"
#include "irforge/enrichment/HashEngine.hpp"
#include <cmath>
#include <set>
namespace irforge {
namespace {
Json blank(const std::string &host) {
    return {{"schema_version", 1},
            {"host_id", host},
            {"mode", "disabled"},
            {"samples", 0},
            {"smoothing", 1.0},
            {"rare_fraction", 0.01},
            {"max_age_days", 30},
            {"features", Json::object()},
            {"updated_at", formatUtc(utcNow())},
            {"interpretation", "host-local frequency; rarity does not establish compromise"}};
}
} // namespace
BaselineEngine::BaselineEngine(StoreWorker &store, std::string host, int minimum)
    : store_(store), host_(std::move(host)), minimum_(minimum) {
    if (minimum < 1 || minimum > 100000)
        throw std::runtime_error("baseline sample bound invalid");
    document_ = store_.call({{"op", "get"}, {"table", "baselines"}, {"key", host_}});
    if (document_.is_null())
        document_ = blank(host_);
    validate(document_, host_);
    for (const auto &hist : document_["features"])
        for (auto entry = hist.begin(); entry != hist.end(); ++entry)
            featureBytes_ += entry.key().size() + 64;
    controlRevision_ = document_.value("control_revision", std::string{});
    auto priorMode = document_["mode"];
    tick(utcNow());
    if (document_["mode"] != priorMode)
        flush();
}
Json BaselineEngine::features(const SecurityEvent &e) {
    Json result = Json::object();
    if (auto p = std::get_if<ProcessPayload>(&e.payload);
        p && e.type == EventType::ProcessStart && !p->initialEnumeration) {
        if (p->imagePath)
            result["image_path"] = normalizePath(*p->imagePath);
        if (p->imagePath && p->parentImagePath)
            result["parent_child"] = baseName(*p->parentImagePath) + " -> " + baseName(*p->imagePath);
        result["execution_hour_utc"] = std::to_string((e.timestampUtc / 3600000) % 24);
    }
    if (auto n = std::get_if<TcpPayload>(&e.payload);
        n && !n->firstSnapshot && e.type != EventType::TcpConnectionClosed)
        result["network_destination"] = lower(n->remoteAddress) + ":" + std::to_string(n->remotePort);
    if (auto f = std::get_if<FilePayload>(&e.payload); f && e.type == EventType::ArtifactEnriched) {
        if (f->metadata.contains("signature")) {
            const auto &sig = f->metadata["signature"];
            if (sig.contains("signer") && sig["signer"].is_string())
                result["signer"] = sig["signer"];
            if (f->metadata.contains("hash") &&
                f->metadata["hash"].value("status", std::string{}) == "complete")
                result["hash_signer_path"] = f->metadata["hash"].value("sha256", std::string{}) + "|" +
                                             sig.value("status", std::string{}) + "|" +
                                             normalizePath(f->path);
        }
    }
    if (auto i = std::get_if<InventoryPayload>(&e.payload); i && !i->after.is_null()) {
        auto bytes = i->after.dump();
        result["persistence_artifact"] =
            i->kind + "/" + lower(i->key).substr(0, 3500) + "/" +
            sha256Bytes(std::span(reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size()));
    }
    if (auto f = std::get_if<FilePayload>(&e.payload);
        f && (e.type == EventType::FileCreated || e.type == EventType::FileModified ||
              e.type == EventType::FileDeleted || e.type == EventType::FileRenamed)) {
        auto path = normalizePath(f->path);
        auto directory = path.substr(0, path.find_last_of("\\/"));
        result["file_activity"] = directory.substr(0, 3500) + "/" + eventTypeName(e.type) + "/hour-" +
                                  std::to_string((e.timestampUtc / 3600000) % 24);
    }
    return result;
}
void BaselineEngine::validate(const Json &j, const std::string &host) {
    validateDocument(j, 4 * 1048576);
    if (j.contains("learning_ends_at"))
        (void)parseUtc(j.at("learning_ends_at").get<std::string>());
    auto smoothing = j.value("smoothing", 1.0), rare = j.value("rare_fraction", 0.01);
    auto age = j.value("max_age_days", 30);
    if (!std::isfinite(smoothing) || smoothing <= 0 || smoothing > 100 || !std::isfinite(rare) || rare < 0 ||
        rare > 0.1 || age < 1 || age > 3650)
        throw std::runtime_error("baseline smoothing/rarity/age policy outside bounds");
    if (j.at("schema_version") != 1 || j.at("host_id") != host ||
        !std::set<std::string>{"disabled", "learning", "frozen"}.contains(j.at("mode").get<std::string>()) ||
        (!j.at("samples").is_number_unsigned() &&
         (!j.at("samples").is_number_integer() || j.at("samples").get<std::int64_t>() < 0)))
        throw std::runtime_error("invalid baseline host/version/mode/count");
    if (!j.at("features").is_object() || j["features"].size() > 8)
        throw std::runtime_error("invalid baseline features");
    std::size_t total = 0;
    for (auto it = j["features"].begin(); it != j["features"].end(); ++it) {
        if (!std::set<std::string>{"image_path", "parent_child", "execution_hour_utc", "network_destination",
                                   "signer", "hash_signer_path", "persistence_artifact", "file_activity"}
                 .contains(it.key()) ||
            !it.value().is_object())
            throw std::runtime_error("unknown baseline feature");
        for (auto row = it.value().begin(); row != it.value().end(); ++row) {
            if (++total > 10000 || row.key().size() > 4096 || !row.value().is_number_integer() ||
                row.value().get<std::int64_t>() < 1)
                throw std::runtime_error("invalid baseline histogram");
        }
    }
}
void BaselineEngine::learn(bool opt, int duration, Millis now) {
    if (!opt)
        throw std::runtime_error("baseline learning requires explicit opt-in");
    if (duration < 0 || duration > 604800)
        throw std::runtime_error("baseline duration must be 0 (manual freeze) or 1..604800 seconds");
    document_.erase("learning_ends_at");
    document_.erase("learning_finished_at");
    if (duration)
        document_["learning_ends_at"] = formatUtc(now + static_cast<Millis>(duration) * 1000);
    document_["mode"] = "learning";
    document_["learning_started_at"] = formatUtc(now);
    document_["model_version"] = newUuid();
    document_["minimum_samples"] = minimum_;
    auto health = store_.call({{"op", "get"}, {"table", "health"}, {"key", "collection"}});
    document_["training_start_coverage"] = health.is_null() ? Json{{"state", "unavailable"}} : health;
    document_["control_revision"] = newUuid();
    flush();
}
void BaselineEngine::freeze() {
    document_.erase("learning_ends_at");
    document_["mode"] = "frozen";
    document_["control_revision"] = newUuid();
    flush();
}
void BaselineEngine::reset(bool confirm) {
    if (!confirm)
        throw std::runtime_error("baseline reset requires explicit confirmation");
    document_ = blank(host_);
    featureBytes_ = 0;
    document_["control_revision"] = newUuid();
    flush();
}
Json BaselineEngine::compare(const SecurityEvent &e) const {
    Json result = {{"mode", document_["mode"]},
                   {"samples", document_["samples"]},
                   {"ready", false},
                   {"deviations", Json::array()}};
    if (document_["mode"] != "frozen" ||
        document_["samples"].get<std::uint64_t>() < static_cast<std::uint64_t>(minimum_))
        return result;
    result["reference_age_seconds"] =
        std::max<Millis>(0, utcNow() - parseUtc(document_.at("updated_at").get<std::string>())) / 1000;
    result["stale"] = result["reference_age_seconds"].get<Millis>() >
                      static_cast<Millis>(document_.value("max_age_days", 30)) * 86400;
    if (result["stale"].get<bool>()) {
        result["reason"] = "reference older than configured policy; refresh before comparing";
        return result;
    }
    result["ready"] = true;
    auto observed = features(e);
    for (auto it = observed.begin(); it != observed.end(); ++it) {
        const auto &hist = document_["features"];
        auto value = it.value().get<std::string>();
        std::uint64_t count = hist.contains(it.key()) && hist[it.key()].contains(value)
                                  ? hist[it.key()][value].get<std::uint64_t>()
                                  : 0;
        auto sampleCount = document_["samples"].get<std::uint64_t>();
        auto categories = hist.contains(it.key()) ? hist[it.key()].size() + 1 : 1;
        auto smoothing = document_.value("smoothing", 1.0);
        auto smoothed = (count + smoothing) / (sampleCount + smoothing * categories);
        if (!count || static_cast<double>(count) / sampleCount < document_.value("rare_fraction", 0.01))
            result["deviations"].push_back(
                {{"feature", it.key()},
                 {"value", value},
                 {"count", count},
                 {"smoothed_frequency", smoothed},
                 {"confidence", "low"},
                 {"interpretation", count ? "rare learned observation; review context"
                                          : "first observed against frozen baseline; review context"}});
    }
    return result;
}
std::vector<SecurityEvent> BaselineEngine::observe(const SecurityEvent &e) {
    tick(utcNow());
    if (!e.hostId.empty() && e.hostId != host_)
        throw std::runtime_error("baseline cannot mix host identities");
    std::vector<SecurityEvent> out;
    if (document_["mode"] == "learning")
        if (std::holds_alternative<StatusPayload>(e.payload)) {
            auto &states = document_["observed_source_states"];
            if (states.is_null())
                states = Json::object();
            if (states.size() < 32 || states.contains(e.source))
                states[e.source] = Json(e)["payload"];
        }
    auto f = features(e);
    if (document_["mode"] == "learning" && !f.empty()) {
        std::size_t total = 0;
        for (const auto &hist : document_["features"])
            total += hist.size();
        for (auto it = f.begin(); it != f.end(); ++it) {
            auto &hist = document_["features"][it.key()];
            if (hist.is_null())
                hist = Json::object();
            auto value = it.value().get<std::string>();
            if (!hist.contains(value) && (total >= 10000 || featureBytes_ + value.size() + 64 > 512 * 1024)) {
                document_["skipped_feature_values"] = document_.value("skipped_feature_values", 0ULL) + 1;
                continue;
            }
            auto &count = hist[value];
            if (count.is_null()) {
                count = 1;
                ++total;
                featureBytes_ += value.size() + 64;
            } else if (count.get<std::uint64_t>() < 1000000000)
                count = count.get<std::uint64_t>() + 1;
        }
        document_["samples"] =
            std::min<std::uint64_t>(1000000000, document_["samples"].get<std::uint64_t>() + 1);
        document_["updated_at"] = formatUtc(utcNow());
    } else {
        auto result = compare(e);
        for (const auto &deviation : result["deviations"]) {
            SecurityEvent d;
            d.schemaVersion = 2;
            d.type = EventType::BaselineDeviation;
            d.timestampUtc = e.timestampUtc;
            d.source = "baseline";
            d.hostId = host_;
            d.attributionMethod = "host_local_frequency";
            d.attributionConfidence = "low";
            auto fields = deviation;
            fields["observed_event_id"] = e.uniqueId;
            fields["minimum_samples"] = minimum_;
            d.payload = ObservationPayload{fields};
            out.push_back(d);
        }
    }
    return out;
}
Json BaselineEngine::exportData() const { return document_; }
void BaselineEngine::importData(const Json &j, bool confirm) {
    if (!confirm)
        throw std::runtime_error("baseline import requires explicit confirmation");
    validate(j, host_);
    document_ = j;
    document_["mode"] = "frozen";
    document_["control_revision"] = newUuid();
    flush();
}
void BaselineEngine::flush() {
    tick(utcNow());
    document_ = store_.call({{"op", "baseline_flush"},
                             {"key", host_},
                             {"expected_control_revision", controlRevision_},
                             {"data", document_}});
    controlRevision_ = document_.value("control_revision", std::string{});
    featureBytes_ = 0;
    for (const auto &hist : document_["features"])
        for (auto entry = hist.begin(); entry != hist.end(); ++entry)
            featureBytes_ += entry.key().size() + 64;
}
void BaselineEngine::tick(Millis now) {
    if (document_["mode"] == "learning" && document_.contains("learning_ends_at") &&
        now >= parseUtc(document_["learning_ends_at"].get<std::string>())) {
        document_["mode"] = "frozen";
        document_["control_revision"] = newUuid();
        document_["learning_finished_at"] = formatUtc(now);
    }
}
} // namespace irforge
