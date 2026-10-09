#pragma once
#include "Event.hpp"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
namespace irforge {
class EventBus {
    const std::size_t capacity_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<SecurityEvent> queue_;
    bool closed_ = false;
    std::atomic<std::uint64_t> dropped_{};

  public:
    explicit EventBus(std::size_t);
    bool publish(SecurityEvent);
    std::optional<SecurityEvent> pop();
    std::optional<SecurityEvent> popFor(std::chrono::milliseconds);
    bool drained();
    std::size_t depth();
    void close();
    std::uint64_t dropped() const { return dropped_.load(); }
};
} // namespace irforge
