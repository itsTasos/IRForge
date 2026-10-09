#pragma once
#include "IMonitor.hpp"
namespace irforge {
// Decoder is shared by the real IOCP collector and negative/overflow fixtures.
struct DirectoryNotice {
    std::uint32_t action{};
    std::string name;
};
std::vector<DirectoryNotice> decodeDirectoryNotices(const std::vector<std::uint8_t> &);
#ifdef _WIN32
class FileMonitor final : public IMonitor {
    struct Impl;
    std::unique_ptr<Impl> impl_;

  public:
    FileMonitor(EventBus &, const Config &);
    ~FileMonitor();
    void start() override;
    void stop() noexcept override;
};
#endif
} // namespace irforge
