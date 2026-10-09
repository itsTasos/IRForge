#pragma once
#include "irforge/core/Schema.hpp"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
namespace irforge {
class SqliteStore {
    struct Impl;
    std::unique_ptr<Impl> impl_;

  public:
    explicit SqliteStore(const std::string &path, std::uint64_t maxBytes = 2ULL * 1024 * 1024 * 1024);
    ~SqliteStore();
    SqliteStore(const SqliteStore &) = delete;
    void session(const std::string &host, const std::string &id, const Json &metadata);
    std::string event(const Json &v2);
    void incident(Json);
    Json query(const std::string &table, const Json &filters = Json::object(), int limit = 100,
               int offset = 0);
    Json detail(const std::string &id);
    void annotate(const std::string &id, const std::string &author, const std::string &text,
                  const std::string &state);
    Json get(const std::string &table, const std::string &key);
    void put(const std::string &table, const std::string &key, const Json &, Millis expires = 0);
    void audit(const std::string &author, const Json &);
    Json createCase(const std::string &title, const std::vector<std::string> &incidents,
                    const std::string &author);
    Json health();
    Json retention(Millis now, int eventDays = 14, int incidentDays = 90, int spoolDays = 7);
    void checkpoint();
    void spool(const Json &packet);
    Json spoolNext(int limit = 100);
    void spoolAck(const std::string &agent, const std::string &session, std::uint64_t sequence);
    Json request(const Json &);
};
// One owner thread opens, mutates and queries the durable DB. Collectors never
// call SQLite. Overload is explicit; shutdown drains accepted writes.
class StoreWorker {
    struct Work {
        Json request;
        std::shared_ptr<std::promise<Json>> result;
    };
    std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<Work> queue_;
    std::size_t capacity_;
    bool closing_ = false;
    std::jthread thread_;
    std::atomic<std::uint64_t> dropped_{}, failures_{};
    std::atomic<std::uint64_t> processed_{}, lastMicros_{};

  public:
    StoreWorker(const std::string &path, std::size_t capacity = 10000,
                std::uint64_t maxBytes = 2ULL * 1024 * 1024 * 1024);
    ~StoreWorker();
    bool enqueue(Json);
    std::future<Json> submit(Json);
    Json call(Json);
    void flush();
    Json stats();
    std::uint64_t dropped() const { return dropped_; }
    std::uint64_t failures() const { return failures_; }
};
} // namespace irforge
