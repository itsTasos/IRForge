#pragma once
#include "irforge/core/Event.hpp"
#include <memory>
#include <stop_token>
namespace irforge {
class YaraScanner {
    struct Impl;
    std::unique_ptr<Impl> impl_;

  public:
    explicit YaraScanner(const std::string &approvedRules, int timeoutSeconds = 10,
                         std::uint64_t maxBytes = 100ULL * 1024 * 1024, int maxCpuPercent = 20);
    ~YaraScanner();
    Json scan(const std::string &file, std::stop_token = {});
    void reload();
    Json health() const;
};
// Internal framed stdin/stdout worker. The controller places this process in a
// kill-on-close job with memory and process limits and enforces a hard deadline.
int yaraWorker(const std::string &approvedRules);
} // namespace irforge
