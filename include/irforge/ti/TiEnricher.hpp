#pragma once
#include "VirusTotal.hpp"
#include "irforge/core/Config.hpp"
#include "irforge/core/EventBus.hpp"
namespace irforge {
class TiEnricher {
    StoreWorker &store_;
    EventBus &bus_;
    Config config_;
    mutable std::mutex mutex_;
    std::condition_variable_any ready_;
    std::deque<Json> queue_;
    std::jthread worker_;
    std::atomic<std::uint64_t> skipped_{};

  public:
    TiEnricher(StoreWorker &, EventBus &, const Config &);
    ~TiEnricher();
    bool consider(const SecurityEvent &);
    void stop() noexcept;
    Json health() const;
};
} // namespace irforge
