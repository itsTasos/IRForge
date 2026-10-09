#pragma once
#include "irforge/storage/SqliteStore.hpp"
namespace irforge {
class BaselineEngine {
    std::string controlRevision_;
    StoreWorker &store_;
    std::string host_;
    Json document_;
    int minimum_;
    std::size_t featureBytes_ = 0;

  public:
    BaselineEngine(StoreWorker &, std::string host, int minimumSamples = 20);
    static Json features(const SecurityEvent &);
    static void validate(const Json &, const std::string &host);
    void learn(bool explicitOptIn, int durationSeconds = 0, Millis now = utcNow());
    void tick(Millis now);
    void freeze();
    void reset(bool explicitConfirm);
    std::vector<SecurityEvent> observe(const SecurityEvent &);
    Json compare(const SecurityEvent &) const;
    Json exportData() const;
    void importData(const Json &, bool explicitConfirm);
    void flush();
};
} // namespace irforge
