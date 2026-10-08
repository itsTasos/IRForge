#pragma once
#include "irforge/core/Config.hpp"
#include "irforge/core/EventBus.hpp"
#include <memory>
namespace irforge {
class IMonitor {
  public:
    virtual ~IMonitor() = default;
    virtual void start() = 0;
    virtual void stop() noexcept = 0;
};
#ifdef _WIN32
class ProcessMonitor final : public IMonitor {
    struct Impl;
    std::unique_ptr<Impl> impl_;

  public:
    ProcessMonitor(EventBus &, const Config &);
    ~ProcessMonitor();
    void start() override;
    void stop() noexcept override;
};
class NetworkMonitor final : public IMonitor {
    struct Impl;
    std::unique_ptr<Impl> impl_;

  public:
    NetworkMonitor(EventBus &, const Config &);
    ~NetworkMonitor();
    void start() override;
    void stop() noexcept override;
};
class RegistryMonitor final : public IMonitor {
    struct Impl;
    std::unique_ptr<Impl> impl_;

  public:
    RegistryMonitor(EventBus &, const Config &);
    ~RegistryMonitor();
    void start() override;
    void stop() noexcept override;
};
void enrichProcess(SecurityEvent &);
#endif
} // namespace irforge
