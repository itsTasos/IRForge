#include "irforge/core/EventBus.hpp"
#include <stdexcept>
namespace irforge {
std::size_t EventBus::depth() {
    std::lock_guard lock(mutex_);
    return queue_.size();
}
EventBus::EventBus(std::size_t n) : capacity_(n) {
    if (!n)
        throw std::invalid_argument("queue capacity is zero");
}
bool EventBus::publish(SecurityEvent e) {
    std::lock_guard lock(mutex_);
    if (closed_ || queue_.size() >= capacity_) {
        ++dropped_;
        return false;
    }
    queue_.push_back(std::move(e));
    cv_.notify_one();
    return true;
}
std::optional<SecurityEvent> EventBus::pop() {
    std::unique_lock lock(mutex_);
    cv_.wait(lock, [&] { return closed_ || !queue_.empty(); });
    if (queue_.empty())
        return std::nullopt;
    auto e = std::move(queue_.front());
    queue_.pop_front();
    return e;
}
void EventBus::close() {
    std::lock_guard lock(mutex_);
    closed_ = true;
    cv_.notify_all();
}
std::optional<SecurityEvent> EventBus::popFor(std::chrono::milliseconds timeout) {
    std::unique_lock lock(mutex_);
    cv_.wait_for(lock, timeout, [&] { return closed_ || !queue_.empty(); });
    if (queue_.empty())
        return {};
    auto e = std::move(queue_.front());
    queue_.pop_front();
    return e;
}
bool EventBus::drained() {
    std::lock_guard lock(mutex_);
    return closed_ && queue_.empty();
}
} // namespace irforge
