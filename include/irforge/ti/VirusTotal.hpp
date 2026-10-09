#pragma once
#include "irforge/storage/SqliteStore.hpp"
namespace irforge {
struct HttpResponse {
    int status{};
    std::string body, retryAfter;
};
using TiTransport = std::function<HttpResponse(const std::string &path, const std::string &apiKey)>;
class VirusTotalClient {
    StoreWorker &store_;
    bool productionTransport_;
    TiTransport transport_;

  public:
    explicit VirusTotalClient(StoreWorker &, TiTransport = {});
    static bool validHash(const std::string &);
    static bool publicIp(const std::string &);
    Json lookup(const std::string &kind, const std::string &indicator, bool explicitOptIn,
                const std::string &credentialTarget = "IRForge.VirusTotal.v1", Millis now = utcNow());
};
void saveTiCredential(const std::string &target, const std::string &key);
std::string loadTiCredential(const std::string &target);
void removeTiCredential(const std::string &target);
HttpResponse virusTotalGet(const std::string &path, const std::string &apiKey);
Json parseIocCsv(const std::string &text, const std::string &source);
class IocMatcher {
    Json feed_;

  public:
    explicit IocMatcher(Json reviewedFeed);
    Json match(const std::string &kind, const std::string &value, Millis now = utcNow()) const;
    const Json &feed() const { return feed_; }
};
} // namespace irforge
