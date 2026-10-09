#pragma once
#include "irforge/detection/RuleEngine.hpp"
#include "irforge/storage/SqliteStore.hpp"
namespace irforge {
struct LocalPrincipal {
    std::string sid;
    bool administrator = false;
};
class OperationGateway {
    StoreWorker &store_;
    RuleEngine rules_;
    std::string rulesDirectory_;
    std::string configurationPath_;
    std::string liveHost_;
    std::mutex rulesMutex_;
    std::atomic<bool> rulesChanged_{false};
    std::atomic<bool> baselinesChanged_{false};
    std::mutex tiMutex_;
    std::condition_variable_any tiReady_;
    std::deque<Json> tiQueue_;
    std::jthread tiWorker_;

  public:
    OperationGateway(StoreWorker &, const std::string &rulesDirectory,
                     const std::string &configurationPath = "", const std::string &liveHost = "");
    Json dispatch(const Json &, const LocalPrincipal &);
    RuleEngine ruleSnapshot();
    bool consumeRuleChanges() { return rulesChanged_.exchange(false); }
    bool consumeBaselineChanges() { return baselinesChanged_.exchange(false); }
};
class PipeServer {
    struct Impl;
    std::unique_ptr<Impl> impl_;

  public:
    PipeServer(const std::string &name, OperationGateway &, const std::vector<std::string> &readerSids = {});
    ~PipeServer();
    void start();
    void stop() noexcept;
};
Json pipeRequest(const std::string &name, const Json &, int timeoutMs = 5000);
std::string currentUserSid();
void validatePipeName(const std::string &);
} // namespace irforge
