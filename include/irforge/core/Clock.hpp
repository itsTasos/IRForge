#pragma once
#include "Event.hpp"
namespace irforge {
class VirtualClock {
    Millis now_{};

  public:
    void advance(Millis t);
    Millis now() const { return now_; }
};
} // namespace irforge
