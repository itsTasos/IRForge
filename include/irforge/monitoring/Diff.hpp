#pragma once
#include "irforge/core/Event.hpp"
#include <map>
#include <set>
namespace irforge {
class NetworkDiff {
    std::map<std::string, TcpPayload> previous_;
    bool initialized_ = false;

  public:
    std::vector<SecurityEvent> update(const std::vector<TcpPayload> &, Millis, bool success = true);
};
struct RegistrySnapshot {
    std::map<std::string, std::map<std::string, RegistryValue>> keys;
};
std::vector<SecurityEvent> registryDiff(const RegistrySnapshot &, const RegistrySnapshot &,
                                        const std::string &hive, const std::string &view, Millis);
RegistryValue decodeRegistryValue(std::uint32_t, const std::vector<std::uint8_t> &);
} // namespace irforge
