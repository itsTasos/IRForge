#pragma once
#include "irforge/core/Config.hpp"
#include "irforge/core/EventBus.hpp"
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
namespace irforge {
class ArtifactEnricher {
    EventBus &bus_;
    Config config_;
    mutable std::mutex mutex_;
    std::condition_variable_any ready_;
    std::deque<std::pair<std::string, std::string>> pending_;
    std::vector<std::jthread> workers_;
    std::atomic<std::uint64_t> skipped_{}, completed_{};

  public:
    ArtifactEnricher(EventBus &, const Config &);
    ~ArtifactEnricher();
    bool consider(const SecurityEvent &);
    void stop() noexcept;
    Json health() const;
};
} // namespace irforge
