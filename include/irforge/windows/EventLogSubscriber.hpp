#pragma once
#include "irforge/monitoring/IMonitor.hpp"
#include "irforge/storage/SqliteStore.hpp"
namespace irforge {
struct ProviderRecord {
    std::string provider, channel, recordId, timestamp, host;
    std::uint32_t eventId{};
    std::map<std::string, std::string> data;
    Json unmapped = Json::object();
};
ProviderRecord parseProviderXml(const std::string &);
std::vector<SecurityEvent> normalizeProviderRecord(const ProviderRecord &);
Millis parseProviderUtc(const std::string &);
#ifdef _WIN32
class EventLogMonitor final : public IMonitor {
    struct Impl;
    std::unique_ptr<Impl> impl_;

  public:
    EventLogMonitor(EventBus &, const Config &, StoreWorker &);
    ~EventLogMonitor();
    void start() override;
    void stop() noexcept override;
};
std::vector<SecurityEvent> importEventLog(const std::string &);
#endif
} // namespace irforge
