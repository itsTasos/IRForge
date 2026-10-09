#pragma once
#include "IMonitor.hpp"
#include <map>
namespace irforge {
using InventoryEntries = std::map<std::string, Json>;
struct InventoryResult {
    InventoryEntries entries;
    std::vector<std::string> gaps;
    bool complete = true;
};
std::vector<SecurityEvent> diffInventory(const std::string &kind, const InventoryEntries &before,
                                         const InventoryEntries &after, bool initial, Millis now);
#ifdef _WIN32
InventoryResult inventoryServices();
InventoryResult inventoryTasks();
InventoryResult inventoryStartup();
InventoryResult inventoryExtendedRegistry();
Json inventoryProcesses();
Json inventorySockets();
class InventoryMonitor final : public IMonitor {
    struct Impl;
    std::unique_ptr<Impl> impl_;

  public:
    InventoryMonitor(EventBus &, const Config &);
    ~InventoryMonitor();
    void start() override;
    void stop() noexcept override;
};
#endif
} // namespace irforge
