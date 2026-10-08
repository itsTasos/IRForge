#include "irforge/core/Clock.hpp"
#include <algorithm>
namespace irforge {
void VirtualClock::advance(Millis t) { now_ = std::max(now_, t); }
} // namespace irforge
