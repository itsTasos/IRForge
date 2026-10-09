#pragma once
#include "RemoteProtocol.hpp"
#include <memory>
namespace irforge {
Json tlsRequest(const Json &connection, const std::string &path, const Json &body);
std::optional<int> remoteCommand(const std::vector<std::string> &);
class RemoteSender {
    struct Impl;
    std::unique_ptr<Impl> impl_;

  public:
    RemoteSender(StoreWorker &, const Json &connection);
    ~RemoteSender();
    void stop() noexcept;
};
int collectorApplication(const std::vector<std::string> &);
} // namespace irforge
