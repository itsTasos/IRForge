#include "irforge/ipc/PipeServer.hpp"
#include "irforge/core/Config.hpp"
#include "irforge/detection/BaselineEngine.hpp"
#include "irforge/monitoring/Win32.hpp"
#include "irforge/reporting/Evidence.hpp"
#include "irforge/ti/VirusTotal.hpp"
#include <sddl.h>
#include <set>
namespace irforge {
void validatePipeName(const std::string &name) {
    if (name.empty() || name.size() > 128 ||
        name.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_") !=
            std::string::npos)
        throw std::runtime_error("invalid local pipe name");
}
OperationGateway::OperationGateway(StoreWorker &s, const std::string &r, const std::string &config,
                                   const std::string &liveHost)
    : store_(s), rules_(RuleEngine::load(r)), rulesDirectory_(r), configurationPath_(config),
      liveHost_(liveHost) {
    auto copy = rules_.rules();
    for (auto &rule : copy) {
        auto policy = store_.call({{"op", "get"}, {"table", "settings"}, {"key", "rule/" + rule.id}});
        if (!policy.is_null())
            rule.enabled = policy.at("enabled").get<bool>();
    }
    rules_ = RuleEngine(std::move(copy));
    tiWorker_ = std::jthread([this](std::stop_token stop) {
        while (!stop.stop_requested()) {
            Json job;
            {
                std::unique_lock lock(tiMutex_);
                tiReady_.wait(lock, stop, [this] { return !tiQueue_.empty(); });
                if (stop.stop_requested())
                    break;
                job = tiQueue_.front();
                tiQueue_.pop_front();
            }
            Json result;
            try {
                VirusTotalClient provider(store_);
                result = provider.lookup(job.at("kind"), job.at("indicator"), true,
                                         job.value("target", std::string("IRForge.VirusTotal.v1")));
            } catch (const std::exception &e) {
                result = {{"status", "unavailable"},
                          {"reason", e.what()},
                          {"provider", "virustotal"},
                          {"indicator", job.at("indicator")},
                          {"verdict", "unknown"}};
            }
            result["job_id"] = job.at("job_id");
            result["author"] = job.at("author");
            try {
                store_.call({{"op", "put"},
                             {"table", "health"},
                             {"key", "ti_job/" + job.at("job_id").get<std::string>()},
                             {"data", result}});
            } catch (...) {
            }
        }
    });
}
RuleEngine OperationGateway::ruleSnapshot() {
    std::lock_guard lock(rulesMutex_);
    return rules_;
}
Json OperationGateway::dispatch(const Json &request, const LocalPrincipal &principal) {
    validateDocument(request);
    auto op = request.at("op").get<std::string>();
    const std::map<std::string, std::set<std::string>> keys = {
        {"health", {"op"}},
        {"query", {"op", "table", "filters", "limit", "offset"}},
        {"detail", {"op", "id"}},
        {"rules", {"op"}},
        {"baseline", {"op", "host"}},
        {"annotate", {"op", "id", "text", "state"}},
        {"baseline_change", {"op", "host", "action", "confirm", "opt_in", "duration_seconds"}},
        {"rule_toggle", {"op", "id", "enabled"}},
        {"case_create", {"op", "title", "incident_ids"}}};
    if (op == "ti_lookup") {
        if (!principal.administrator || !request.value("opt_in", false))
            throw std::runtime_error("TI lookup requires explicit opt-in and elevated authorization");
        const std::set<std::string> fields = {"op", "kind", "indicator", "opt_in", "target"};
        for (auto it = request.begin(); it != request.end(); ++it)
            if (!fields.contains(it.key()))
                throw std::runtime_error("unexpected TI lookup field");
        auto kind = request.at("kind").get<std::string>(),
             indicator = request.at("indicator").get<std::string>();
        if ((kind != "sha256" && kind != "ip") ||
            (kind == "sha256" && !VirusTotalClient::validHash(indicator)) ||
            (kind == "ip" && !VirusTotalClient::publicIp(indicator)))
            throw std::runtime_error("only SHA256/public-IP lookup accepted");
        Json job = request;
        job["job_id"] = newUuid();
        job["author"] = principal.sid;
        {
            std::lock_guard lock(tiMutex_);
            if (tiQueue_.size() >= 16)
                throw std::runtime_error("manual TI queue full");
            tiQueue_.push_back(job);
        }
        tiReady_.notify_one();
        store_.call({{"op", "audit"},
                     {"author", principal.sid},
                     {"data",
                      {{"operation", "ti_lookup_queued"},
                       {"indicator", indicator},
                       {"job_id", job["job_id"]},
                       {"file_uploaded", false}}}});
        return {{"status", "queued"}, {"job_id", job["job_id"]}, {"poll", "health evidence table"}};
    }
    // The configuration path is supplied by the running agent, never by the client.
    if (op == "configuration" && principal.administrator) {
        if (configurationPath_.empty())
            throw std::runtime_error("this evidence-only backend has no collection configuration");
        if (request.size() != 2 || !request.contains("config"))
            throw std::runtime_error("configuration request keys invalid");
        auto temporary = filesystemPath(configurationPath_ + ".IRForge-" + newUuid() + ".tmp");
        struct Cleanup {
            std::filesystem::path path;
            ~Cleanup() {
                std::error_code ec;
                std::filesystem::remove(path, ec);
            }
        } cleanup{temporary};
        writeDocument(temporary, request.at("config"));
        auto checked = Config::load(temporary.string());
        store_.call({{"op", "audit"},
                     {"author", principal.sid},
                     {"data", {{"operation", "configuration_next_restart"}, {"config", checked.json()}}}});
        if (!MoveFileExW(temporary.c_str(), filesystemPath(configurationPath_).c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            throw WindowsError(GetLastError(), "configuration atomic replacement");
        return {{"applied", true}, {"effective", "next agent restart; running coverage unchanged"}};
    }
    auto known = keys.find(op);
    if (known == keys.end())
        throw std::runtime_error("unsupported local operation");
    for (auto it = request.begin(); it != request.end(); ++it)
        if (!known->second.contains(it.key()))
            throw std::runtime_error("unexpected local request key " + it.key());
    if (op == "health") {
        auto health = store_.call({{"op", "health"}});
        health["principal"] = {{"sid", principal.sid},
                               {"administrator", principal.administrator},
                               {"default_mode", "read_only"}};
        health["transport"] = "local authenticated named pipe";
        health["collection"] = store_.call({{"op", "get"}, {"table", "health"}, {"key", "collection"}});
        health["effective_config"] =
            store_.call({{"op", "get"}, {"table", "settings"}, {"key", "agent/effective-config"}});
        return health;
    }
    if (op == "query") {
        if (!std::set<std::string>{"events", "incidents", "processes", "artifacts", "hosts", "sessions",
                                   "config_audit", "analyst_notes", "cases", "ti_cache", "health",
                                   "baselines"}
                 .contains(request.at("table").get<std::string>()))
            throw std::runtime_error("table not exposed");
        return store_.call(request);
    }
    if (op == "detail")
        return store_.call(request);
    if (op == "rules") {
        std::lock_guard lock(rulesMutex_);
        Json rows = Json::array();
        for (const auto &r : rules_.rules())
            rows.push_back({{"id", r.id},
                            {"name", r.name},
                            {"type", r.type},
                            {"enabled", r.enabled},
                            {"severity", r.severity},
                            {"points", r.score},
                            {"attack", r.attack},
                            {"description", r.description},
                            {"false_positives", r.falsePositives},
                            {"license", r.license},
                            {"source", r.source}});
        return {{"rows", rows}, {"total", rows.size()}};
    }
    if (op == "baseline")
        return BaselineEngine(store_, request.at("host").get<std::string>()).exportData();
    if (!principal.administrator)
        throw std::runtime_error(
            "operation requires an elevated administrator token; local access defaults to read-only");
    if (op == "annotate") {
        auto r = request;
        r["author"] = principal.sid;
        r["status"] = r.at("state");
        r.erase("state");
        store_.call(r);
        return store_.call({{"op", "detail"}, {"id", request.at("id")}});
    }
    if (op == "case_create") {
        auto r = request;
        r["author"] = principal.sid;
        return store_.call(r);
    }
    if (op == "baseline_change") {
        BaselineEngine baseline(store_, request.at("host").get<std::string>());
        auto action = request.at("action").get<std::string>();
        if (action == "learn" && (liveHost_.empty() || request.at("host") != liveHost_))
            throw std::runtime_error("learning requires the actively collecting agent's own host identity; "
                                     "this backend does not collect that host");
        if (action == "learn")
            baseline.learn(request.value("opt_in", false), request.value("duration_seconds", 0));
        else if (action == "freeze")
            baseline.freeze();
        else if (action == "reset")
            baseline.reset(request.value("confirm", false));
        else
            throw std::runtime_error("unsupported baseline action");
        store_.call({{"op", "audit"}, {"author", principal.sid}, {"data", request}});
        baselinesChanged_ = true;
        return baseline.exportData();
    }
    if (op == "rule_toggle") {
        std::lock_guard lock(rulesMutex_);
        auto id = request.at("id").get<std::string>();
        bool enabled = request.at("enabled").get<bool>();
        bool found = false;
        for (const auto &r : rules_.rules())
            if (r.id == id)
                found = true;
        if (!found)
            throw std::runtime_error("rule not found");
        store_.call(
            {{"op", "put"}, {"table", "settings"}, {"key", "rule/" + id}, {"data", {{"enabled", enabled}}}});
        store_.call({{"op", "audit"}, {"author", principal.sid}, {"data", request}});
        auto copy = rules_.rules();
        for (auto &r : copy)
            if (r.id == id)
                r.enabled = enabled;
        rules_ = RuleEngine(std::move(copy));
        rulesChanged_ = true;
        return {{"applied", true}, {"id", id}, {"enabled", enabled}, {"scope", "stored agent rule policy"}};
    }
    throw std::runtime_error("operation unavailable");
}
#ifdef _WIN32
namespace {
std::string tokenSid(HANDLE token) {
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (size == 0 || size > 65536)
        throw WindowsError(GetLastError(), "token identity size");
    std::vector<std::uint8_t> data(size);
    if (!GetTokenInformation(token, TokenUser, data.data(), size, &size))
        throw WindowsError(GetLastError(), "token identity");
    LPWSTR text{};
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(data.data())->User.Sid, &text))
        throw WindowsError(GetLastError(), "SID encoding");
    auto sid = utf8(text);
    LocalFree(text);
    return sid;
}
void io(HANDLE pipe, void *data, DWORD size, bool write, std::stop_token stop, int timeout) {
    DWORD done = 0;
    auto deadline = GetTickCount64() + static_cast<ULONGLONG>(timeout);
    while (done < size) {
        Handle signal(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!signal.value)
            throw WindowsError(GetLastError(), "pipe I/O event");
        OVERLAPPED ov{};
        ov.hEvent = signal.value;
        DWORD bytes = 0;
        bool ok = write ? WriteFile(pipe, static_cast<char *>(data) + done, size - done, &bytes, &ov) != 0
                        : ReadFile(pipe, static_cast<char *>(data) + done, size - done, &bytes, &ov) != 0;
        if (!ok && GetLastError() != ERROR_IO_PENDING)
            throw WindowsError(GetLastError(), "pipe transfer");
        if (!ok) {
            while (!stop.stop_requested() && GetTickCount64() < deadline &&
                   WaitForSingleObject(signal.value, 50) == WAIT_TIMEOUT) {
            }
            if (stop.stop_requested() || GetTickCount64() >= deadline) {
                CancelIoEx(pipe, &ov);
                GetOverlappedResult(pipe, &ov, &bytes, TRUE);
                throw std::runtime_error("pipe request cancelled or timed out");
            }
            if (!GetOverlappedResult(pipe, &ov, &bytes, FALSE))
                throw WindowsError(GetLastError(), "pipe I/O result");
        }
        if (!bytes)
            throw std::runtime_error("pipe peer closed");
        done += bytes;
    }
}
void writeFrame(HANDLE pipe, const Json &j, std::stop_token stop, int timeout) {
    auto text = j.dump();
    if (text.empty() || text.size() > 1048576)
        throw std::runtime_error("IPC response exceeds 1 MiB; reduce page size");
    auto length = static_cast<std::uint32_t>(text.size());
    io(pipe, &length, 4, true, stop, timeout);
    io(pipe, text.data(), length, true, stop, timeout);
}
Json readFrame(HANDLE pipe, std::stop_token stop, int timeout) {
    std::uint32_t length = 0;
    io(pipe, &length, 4, false, stop, timeout);
    if (length == 0 || length > 1048576)
        throw std::runtime_error("IPC frame size rejected");
    std::string text(length, '\0');
    io(pipe, text.data(), length, false, stop, timeout);
    auto j = Json::parse(text, [](int depth, Json::parse_event_t, Json &) {
        if (depth > 32)
            throw std::runtime_error("IPC JSON nesting exceeds 32");
        return true;
    });
    validateDocument(j);
    return j;
}
LocalPrincipal authenticate(HANDLE pipe) {
    if (!ImpersonateNamedPipeClient(pipe))
        throw WindowsError(GetLastError(), "pipe impersonation");
    HANDLE raw{};
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
        auto error = GetLastError();
        RevertToSelf();
        throw WindowsError(error, "client token");
    }
    Handle token(raw);
    LocalPrincipal principal;
    try {
        principal.sid = tokenSid(token.value);
        DWORD size = 0;
        TOKEN_ELEVATION elevation{};
        if (!GetTokenInformation(token.value, TokenElevation, &elevation, sizeof(elevation), &size))
            throw WindowsError(GetLastError(), "client elevation");
        SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
        PSID admin{};
        if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0,
                                      0, 0, 0, &admin))
            throw WindowsError(GetLastError(), "admin SID");
        BOOL member = FALSE;
        bool checked = CheckTokenMembership(token.value, admin, &member) != 0;
        FreeSid(admin);
        if (!checked)
            throw WindowsError(GetLastError(), "client membership");
        principal.administrator = elevation.TokenIsElevated && member;
        RevertToSelf();
        return principal;
    } catch (...) {
        RevertToSelf();
        throw;
    }
}
} // namespace
std::string currentUserSid() {
    HANDLE raw{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
        throw WindowsError(GetLastError(), "own token");
    Handle token(raw);
    return tokenSid(token.value);
}
struct PipeServer::Impl {
    std::string name;
    OperationGateway &gateway;
    PSECURITY_DESCRIPTOR descriptor{};
    std::jthread worker;
    std::mutex mutex;
    std::string failure;
    Impl(std::string n, OperationGateway &g, const std::vector<std::string> &sids)
        : name(std::move(n)), gateway(g) {
        validatePipeName(name);
        std::set<std::string> readers(sids.begin(), sids.end());
        readers.insert(currentUserSid());
        if (readers.size() > 32)
            throw std::runtime_error("too many pipe reader SIDs");
        std::wstring acl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
        for (const auto &sid : readers) {
            PSID parsed{};
            if (!ConvertStringSidToSidW(utf16(sid).c_str(), &parsed))
                throw std::runtime_error("invalid configured reader SID");
            bool valid = IsValidSid(parsed) != 0;
            LocalFree(parsed);
            if (!valid || sid == "S-1-1-0" || sid == "S-1-5-7")
                throw std::runtime_error("anonymous/world pipe reader not allowed");
            acl += L"(A;;GRGW;;;" + utf16(sid) + L")";
        }
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &descriptor,
                                                                  nullptr))
            throw WindowsError(GetLastError(), "pipe DACL");
    }
    ~Impl() {
        if (descriptor)
            LocalFree(descriptor);
    }
};
PipeServer::PipeServer(const std::string &n, OperationGateway &g, const std::vector<std::string> &s)
    : impl_(std::make_unique<Impl>(n, g, s)) {}
PipeServer::~PipeServer() { stop(); }
void PipeServer::start() {
    auto &p = *impl_;
    if (p.worker.joinable())
        throw std::runtime_error("pipe server already running");
    std::promise<void> ready;
    auto future = ready.get_future();
    p.worker = std::jthread([&p, ready = std::move(ready)](std::stop_token stop) mutable {
        bool first = true;
        try {
            while (!stop.stop_requested()) {
                SECURITY_ATTRIBUTES attributes{sizeof(attributes), p.descriptor, FALSE};
                auto path = L"\\\\.\\pipe\\" + utf16(p.name);
                Handle pipe(CreateNamedPipeW(
                    path.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 65536,
                    65536, 5000, &attributes));
                if (pipe.value == INVALID_HANDLE_VALUE)
                    throw WindowsError(GetLastError(), "local named pipe listener");
                if (first) {
                    ready.set_value();
                    first = false;
                }
                Handle signal(CreateEventW(nullptr, TRUE, FALSE, nullptr));
                OVERLAPPED ov{};
                ov.hEvent = signal.value;
                bool connected = ConnectNamedPipe(pipe.value, &ov) != 0;
                auto error = GetLastError();
                if (!connected && error == ERROR_IO_PENDING) {
                    while (!stop.stop_requested() && WaitForSingleObject(signal.value, 50) == WAIT_TIMEOUT) {
                    }
                    if (stop.stop_requested()) {
                        CancelIoEx(pipe.value, &ov);
                        DWORD bytes{};
                        GetOverlappedResult(pipe.value, &ov, &bytes, TRUE);
                        break;
                    }
                    DWORD bytes{};
                    connected = GetOverlappedResult(pipe.value, &ov, &bytes, FALSE) != 0;
                } else if (error == ERROR_PIPE_CONNECTED)
                    connected = true;
                if (!connected)
                    continue;
                try {
                    auto request = readFrame(pipe.value, stop, 5000);
                    auto principal = authenticate(pipe.value);
                    auto result = p.gateway.dispatch(request, principal);
                    writeFrame(pipe.value, {{"ok", true}, {"result", result}}, stop, 5000);
                    auto ack = readFrame(pipe.value, stop, 1000);
                    if (ack != Json{{"ack", true}})
                        throw std::runtime_error("pipe acknowledgment invalid");
                } catch (const std::exception &e) {
                    try {
                        writeFrame(pipe.value, {{"ok", false}, {"error", e.what()}}, stop, 1000);
                        (void)readFrame(pipe.value, stop, 1000);
                    } catch (...) {
                    }
                }
                DisconnectNamedPipe(pipe.value);
            }
        } catch (...) {
            if (first)
                ready.set_exception(std::current_exception());
            else {
                std::lock_guard lock(p.mutex);
                p.failure = "pipe listener failed";
            }
        }
    });
    future.get();
}
void PipeServer::stop() noexcept {
    if (impl_ && impl_->worker.joinable()) {
        impl_->worker.request_stop();
        impl_->worker.join();
    }
}
Json pipeRequest(const std::string &name, const Json &request, int timeout) {
    validatePipeName(name);
    validateDocument(request);
    if (timeout < 100 || timeout > 30000)
        throw std::runtime_error("invalid IPC timeout");
    auto path = L"\\\\.\\pipe\\" + utf16(name);
    auto deadline = GetTickCount64() + static_cast<ULONGLONG>(timeout);
    while (!WaitNamedPipeW(path.c_str(), 50)) {
        auto error = GetLastError();
        if ((error != ERROR_FILE_NOT_FOUND && error != ERROR_SEM_TIMEOUT && error != ERROR_PIPE_BUSY) ||
            GetTickCount64() >= deadline)
            throw WindowsError(error, "agent pipe unavailable");
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    Handle pipe(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
    if (pipe.value == INVALID_HANDLE_VALUE)
        throw WindowsError(GetLastError(), "agent pipe connect");
    ULONG serverPid = 0;
    if (!GetNamedPipeServerProcessId(pipe.value, &serverPid))
        throw WindowsError(GetLastError(), "pipe server identity");
    Handle serverProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, serverPid));
    HANDLE rawServerToken = nullptr;
    if (!serverProcess.value || !OpenProcessToken(serverProcess.value, TOKEN_QUERY, &rawServerToken))
        throw WindowsError(GetLastError(), "pipe server token");
    Handle serverToken(rawServerToken);
    auto serverSid = tokenSid(serverToken.value);
    if (serverSid != currentUserSid() && serverSid != "S-1-5-18")
        throw std::runtime_error("pipe server is neither current user nor local SYSTEM agent");
    writeFrame(pipe.value, request, {}, timeout);
    auto response = readFrame(pipe.value, {}, timeout);
    writeFrame(pipe.value, {{"ack", true}}, {}, timeout);
    if (!response.value("ok", false))
        throw std::runtime_error(response.value("error", std::string("agent request failed")));
    return response.at("result");
}
#else
std::string currentUserSid() { throw std::runtime_error("Windows token required"); }
struct PipeServer::Impl {};
PipeServer::PipeServer(const std::string &, OperationGateway &, const std::vector<std::string> &) {
    throw std::runtime_error("Windows pipe required");
}
PipeServer::~PipeServer() = default;
void PipeServer::start() {}
void PipeServer::stop() noexcept {}
Json pipeRequest(const std::string &, const Json &, int) {
    throw std::runtime_error("Windows pipe required");
}
#endif
} // namespace irforge
