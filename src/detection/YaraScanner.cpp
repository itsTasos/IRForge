#include "irforge/detection/YaraScanner.hpp"
#include "irforge/enrichment/HashEngine.hpp"
#include "irforge/monitoring/Win32.hpp"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <mutex>
#include <thread>
#include <yara_x.h>
namespace irforge {
#ifdef _WIN32
namespace {
std::wstring executable() {
    std::vector<wchar_t> p(32768);
    auto n = GetModuleFileNameW(nullptr, p.data(), static_cast<DWORD>(p.size()));
    if (!n || n >= p.size())
        throw WindowsError(GetLastError(), "executable path");
    return {p.data(), n};
}
std::wstring quoteWindowsArgument(const std::wstring &s) {
    std::wstring result = L"\"";
    unsigned slashes = 0;
    for (auto c : s) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        if (c == L'\"')
            result.append(slashes * 2 + 1, L'\\');
        else
            result.append(slashes, L'\\');
        slashes = 0;
        result += c;
    }
    result.append(slashes * 2, L'\\');
    return result + L"\"";
}
void exact(HANDLE pipe, void *data, DWORD size, bool write) {
    DWORD offset = 0;
    while (offset < size) {
        DWORD transferred = 0;
        bool ok = write ? WriteFile(pipe, static_cast<char *>(data) + offset, size - offset, &transferred,
                                    nullptr) != 0
                        : ReadFile(pipe, static_cast<char *>(data) + offset, size - offset, &transferred,
                                   nullptr) != 0;
        if (!ok || !transferred)
            throw WindowsError(GetLastError(), "YARA framed pipe");
        offset += transferred;
    }
}
void send(HANDLE pipe, const Json &j) {
    auto s = j.dump();
    if (s.size() > 1048576)
        throw std::runtime_error("YARA frame exceeds limit");
    auto n = static_cast<std::uint32_t>(s.size());
    exact(pipe, &n, 4, true);
    exact(pipe, s.data(), n, true);
}
Json receive(HANDLE pipe) {
    std::uint32_t n = 0;
    exact(pipe, &n, 4, false);
    if (n == 0 || n > 1048576)
        throw std::runtime_error("YARA invalid frame length");
    std::string s(n, '\0');
    exact(pipe, s.data(), n, false);
    return Json::parse(s, [](int depth, Json::parse_event_t, Json &) {
        if (depth > 32)
            throw std::runtime_error("YARA request nesting exceeds 32");
        return true;
    });
}
struct Api {
    HMODULE module{};
#define YRX_FUNCTION(name) decltype(&name) name{};
    YRX_FUNCTION(yrx_compiler_create)
    YRX_FUNCTION(yrx_compiler_destroy)
    YRX_FUNCTION(yrx_compiler_add_source_with_origin)
    YRX_FUNCTION(yrx_compiler_errors_json)
    YRX_FUNCTION(yrx_compiler_build)
    YRX_FUNCTION(yrx_rules_destroy)
    YRX_FUNCTION(yrx_rules_count)
    YRX_FUNCTION(yrx_scanner_create)
    YRX_FUNCTION(yrx_scanner_destroy)
    YRX_FUNCTION(yrx_scanner_set_timeout)
    YRX_FUNCTION(yrx_scanner_scan)
    YRX_FUNCTION(yrx_scanner_on_matching_rule)
    YRX_FUNCTION(yrx_rule_identifier)
    YRX_FUNCTION(yrx_rule_iter_metadata)
    YRX_FUNCTION(yrx_buffer_destroy)
#undef YRX_FUNCTION
    template <class F> void symbol(F &f, const char *name) {
        auto address = GetProcAddress(module, name);
        if (!address)
            throw std::runtime_error(std::string("YARA-X C API missing: ") + name);
        static_assert(sizeof(f) == sizeof(address));
        std::memcpy(&f, &address, sizeof(f));
    }
    Api() {
        auto path = std::filesystem::path(executable()).parent_path() / L"yara_x_capi.dll";
        module = LoadLibraryExW(path.c_str(), nullptr,
                                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module)
            throw WindowsError(GetLastError(), "load pinned YARA-X DLL beside executable");
#define YRX_LOAD(name) symbol(name, #name);
        YRX_LOAD(yrx_compiler_create)
        YRX_LOAD(yrx_compiler_destroy)
        YRX_LOAD(yrx_compiler_add_source_with_origin)
        YRX_LOAD(yrx_compiler_errors_json)
        YRX_LOAD(yrx_compiler_build)
        YRX_LOAD(yrx_rules_destroy)
        YRX_LOAD(yrx_rules_count)
        YRX_LOAD(yrx_scanner_create)
        YRX_LOAD(yrx_scanner_destroy)
        YRX_LOAD(yrx_scanner_set_timeout)
        YRX_LOAD(yrx_scanner_scan)
        YRX_LOAD(yrx_scanner_on_matching_rule)
        YRX_LOAD(yrx_rule_identifier) YRX_LOAD(yrx_rule_iter_metadata) YRX_LOAD(yrx_buffer_destroy)
#undef YRX_LOAD
    }
    // The DLL stays loaded until worker exit; Wasmtime installs process-wide
    // exception machinery, so unloading it during active engines is unsafe.
};
struct Program {
    Api api;
    YRX_COMPILER *compiler{};
    YRX_RULES *rules{};
    YRX_SCANNER *scanner{};
    Json matches = Json::array(), pack = Json::array();
    explicit Program(const std::string &dir) {
        if (api.yrx_compiler_create(YRX_DISABLE_INCLUDES | YRX_ERROR_ON_SLOW_PATTERN |
                                        YRX_ERROR_ON_SLOW_LOOP | YRX_ENABLE_CONDITION_OPTIMIZATION,
                                    &compiler) != YRX_SUCCESS)
            throw std::runtime_error("YARA compiler creation failed");
        try {
            std::vector<std::filesystem::path> paths;
            for (const auto &f : std::filesystem::directory_iterator(filesystemPath(dir)))
                if (f.is_regular_file() &&
                    (f.path().extension() == ".yar" || f.path().extension() == ".yara"))
                    paths.push_back(f.path());
            std::sort(paths.begin(), paths.end());
            if (paths.empty() || paths.size() > 128)
                throw std::runtime_error("approved YARA directory must contain 1..128 rule files");
            std::uint64_t total = 0;
            for (const auto &p : paths) {
                auto name = p.u8string();
                std::string origin(name.begin(), name.end());
                if (!pathWithinRoot(origin, dir))
                    throw std::runtime_error("YARA rule escapes approved root");
                auto size = std::filesystem::file_size(p);
                total += size;
                if (size > 1048576 || total > 8 * 1048576)
                    throw std::runtime_error("YARA source size budget exceeded");
                std::ifstream file(p, std::ios::binary);
                std::string source((std::istreambuf_iterator<char>(file)), {});
                if (source.size() != size || source.find('\0') != std::string::npos)
                    throw std::runtime_error("invalid YARA source file");
                if (api.yrx_compiler_add_source_with_origin(compiler, source.c_str(), origin.c_str()) !=
                    YRX_SUCCESS) {
                    YRX_BUFFER *errors{};
                    api.yrx_compiler_errors_json(compiler, &errors);
                    std::string message =
                        errors ? std::string(reinterpret_cast<char *>(errors->data), errors->length)
                               : "compiler error";
                    if (errors)
                        api.yrx_buffer_destroy(errors);
                    throw std::runtime_error(message.substr(0, 16384));
                }
                pack.push_back(
                    {{"file", p.filename().string()}, {"sha256", hashFile(origin, 1048576).sha256}});
            }
            rules = api.yrx_compiler_build(compiler);
            if (!rules || api.yrx_rules_count(rules) > 4096)
                throw std::runtime_error("YARA rule count/compile failure");
            api.yrx_compiler_destroy(compiler);
            compiler = nullptr;
            if (api.yrx_scanner_create(rules, &scanner) != YRX_SUCCESS)
                throw std::runtime_error("YARA scanner creation failed");
            api.yrx_scanner_on_matching_rule(
                scanner,
                [](const YRX_RULE *rule, void *context) {
                    auto &p = *static_cast<Program *>(context);
                    try {
                        const std::uint8_t *id{};
                        std::size_t n = 0;
                        if (p.api.yrx_rule_identifier(rule, &id, &n) != YRX_SUCCESS || n > 512 ||
                            p.matches.size() >= 4096)
                            return;
                        Json match = {{"rule", std::string(reinterpret_cast<const char *>(id), n)},
                                      {"metadata", Json::object()}};
                        p.api.yrx_rule_iter_metadata(
                            rule,
                            [](const YRX_METADATA *m, void *data) {
                                auto &j = *static_cast<Json *>(data);
                                if (j.size() >= 32 || !m->identifier || std::strlen(m->identifier) > 128)
                                    return;
                                switch (m->value_type) {
                                case YRX_I64:
                                    j[m->identifier] = m->value.i64;
                                    break;
                                case YRX_F64:
                                    j[m->identifier] = m->value.f64;
                                    break;
                                case YRX_BOOLEAN:
                                    j[m->identifier] = m->value.boolean;
                                    break;
                                case YRX_STRING:
                                    if (m->value.string && std::strlen(m->value.string) <= 1024)
                                        j[m->identifier] = m->value.string;
                                    break;
                                default:
                                    break;
                                }
                            },
                            &match["metadata"]);
                        p.matches.push_back(match);
                    } catch (...) { /* Never propagate C++ exceptions across the C callback boundary. */
                    }
                },
                this);
        } catch (...) {
            cleanup();
            throw;
        }
    }
    void cleanup() {
        if (scanner)
            api.yrx_scanner_destroy(scanner);
        if (rules)
            api.yrx_rules_destroy(rules);
        if (compiler)
            api.yrx_compiler_destroy(compiler);
        scanner = nullptr;
        rules = nullptr;
        compiler = nullptr;
    }
    ~Program() { cleanup(); }
    Json scan(const Json &request) {
        auto path = request.at("path").get<std::string>();
        auto maximum = request.at("max_bytes").get<std::uint64_t>();
        int seconds = request.at("timeout_seconds").get<int>();
        if (path.size() > 32768 || maximum == 0 || maximum > 1024ULL * 1024 * 1024 || seconds < 1 ||
            seconds > 120)
            throw std::runtime_error("invalid worker scan budget");
        auto stamp = fileIdentityMetadata(path);
        if (stamp.at("size").get<std::uint64_t>() > maximum)
            return {{"status", "skipped_oversized"}, {"matches", Json::array()}};
        std::ifstream file(filesystemPath(path), std::ios::binary);
        if (!file)
            throw std::runtime_error("YARA file unavailable");
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(stamp.at("size").get<std::uint64_t>()));
        file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (static_cast<std::size_t>(file.gcount()) != bytes.size())
            throw std::runtime_error("YARA short file read");
        if (fileIdentityMetadata(path) != stamp)
            return {{"status", "file_changed"}, {"matches", Json::array()}};
        api.yrx_scanner_set_timeout(scanner, static_cast<std::uint64_t>(seconds));
        matches = Json::array();
        auto result = api.yrx_scanner_scan(scanner, bytes.data(), bytes.size());
        auto hash = hashFile(path, maximum);
        if (hash.status != "complete")
            return {{"status", "hash_" + hash.status}, {"matches", Json::array()}};
        if (fileIdentityMetadata(path) != stamp)
            return {{"status", "file_changed"}, {"matches", Json::array()}};
        return {{"status", result == YRX_SUCCESS        ? "complete"
                           : result == YRX_SCAN_TIMEOUT ? "timeout"
                                                        : "scan_error"},
                {"api_result", result},
                {"matches", result == YRX_SUCCESS ? matches : Json::array()},
                {"sha256", hash.sha256},
                {"file", path},
                {"pack", pack},
                {"engine", "YARA-X 1.21.0 official C API"},
                {"strings_retained", false}};
    }
};
} // namespace
struct YaraScanner::Impl {
    std::string approved;
    int timeout;
    int maxCpuPercent;
    std::uint64_t maxBytes;
    Handle process, job, input, output;
    Json metadata;
    mutable std::mutex mutex;
    Impl(std::string r, int t, std::uint64_t m, int cpu)
        : approved(std::move(r)), timeout(t), maxCpuPercent(cpu), maxBytes(m) {
        if (t < 1 || t > 120 || m == 0 || m > 1024ULL * 1024 * 1024 || cpu < 1 || cpu > 100)
            throw std::runtime_error("YARA controller budget invalid");
    }
    void stop() {
        if (process.value) {
            TerminateProcess(process.value, ERROR_CANCELLED);
            WaitForSingleObject(process.value, 3000);
        }
        process = Handle();
        job = Handle();
        input = Handle();
        output = Handle();
    }
    ~Impl() { stop(); }
    Json response(std::stop_token token, int seconds) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
        std::string wire;
        std::uint32_t length = 0;
        while (!token.stop_requested() && std::chrono::steady_clock::now() < deadline) {
            DWORD available = 0;
            if (!PeekNamedPipe(output.value, nullptr, 0, nullptr, &available, nullptr))
                throw WindowsError(GetLastError(), "YARA response pipe");
            if (available) {
                char buffer[8192];
                DWORD got = 0;
                if (!ReadFile(output.value, buffer, std::min<DWORD>(available, sizeof(buffer)), &got,
                              nullptr))
                    throw WindowsError(GetLastError(), "YARA response read");
                wire.append(buffer, got);
                if (wire.size() >= 4 && !length) {
                    std::memcpy(&length, wire.data(), 4);
                    if (!length || length > 1048576)
                        throw std::runtime_error("YARA response frame limit");
                }
                if (length && wire.size() >= 4 + length) {
                    if (wire.size() != 4 + length)
                        throw std::runtime_error("unexpected YARA trailing frame");
                    return Json::parse(wire.substr(4));
                }
            }
            if (WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0)
                throw std::runtime_error("YARA worker terminated before response");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        stop();
        return {{"status", token.stop_requested() ? "cancelled" : "timeout"},
                {"matches", Json::array()},
                {"hard_watchdog", true}};
    }
    void start() {
        Handle readInput, writeOutput, nul;
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
        HANDLE inRead{}, inWrite{}, outRead{}, outWrite{};
        if (!CreatePipe(&inRead, &inWrite, &attributes, 65536))
            throw WindowsError(GetLastError(), "YARA input pipe");
        readInput = Handle(inRead);
        input = Handle(inWrite);
        if (!CreatePipe(&outRead, &outWrite, &attributes, 65536))
            throw WindowsError(GetLastError(), "YARA output pipe");
        output = Handle(outRead);
        writeOutput = Handle(outWrite);
        SetHandleInformation(input.value, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(output.value, HANDLE_FLAG_INHERIT, 0);
        nul = Handle(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes,
                                 OPEN_EXISTING, 0, nullptr));
        job = Handle(CreateJobObjectW(nullptr, nullptr));
        if (!job.value)
            throw WindowsError(GetLastError(), "YARA job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                                  JOB_OBJECT_LIMIT_PROCESS_MEMORY |
                                                  JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        limits.ProcessMemoryLimit = 1024ULL * 1024 * 1024;
        if (!SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
            throw WindowsError(GetLastError(), "YARA job limits");
        JOBOBJECT_BASIC_UI_RESTRICTIONS ui{JOB_OBJECT_UILIMIT_ALL};
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu{};
        cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        cpu.CpuRate = static_cast<DWORD>(maxCpuPercent * 100);
        if (!SetInformationJobObject(job.value, JobObjectCpuRateControlInformation, &cpu, sizeof(cpu)))
            throw WindowsError(GetLastError(), "YARA CPU budget");
        SetInformationJobObject(job.value, JobObjectBasicUIRestrictions, &ui, sizeof(ui));
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        std::vector<std::uint8_t> storage(size);
        auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        if (!InitializeProcThreadAttributeList(list, 1, 0, &size))
            throw WindowsError(GetLastError(), "YARA process attributes");
        HANDLE inherited[] = {readInput.value, writeOutput.value, nul.value};
        if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited,
                                       sizeof(inherited), nullptr, nullptr)) {
            DeleteProcThreadAttributeList(list);
            throw WindowsError(GetLastError(), "YARA inherited handle allowlist");
        }
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = readInput.value;
        startup.StartupInfo.hStdOutput = writeOutput.value;
        startup.StartupInfo.hStdError = nul.value;
        startup.lpAttributeList = list;
        PROCESS_INFORMATION info{};
        auto exe = executable();
        auto command =
            quoteWindowsArgument(exe) + L" _yara-worker --rules " + quoteWindowsArgument(utf16(approved));
        bool launched = CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE,
                                       CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                                       nullptr, nullptr, &startup.StartupInfo, &info) != 0;
        auto error = GetLastError();
        DeleteProcThreadAttributeList(list);
        if (!launched)
            throw WindowsError(error, "YARA worker launch");
        process = Handle(info.hProcess);
        Handle thread(info.hThread);
        if (!AssignProcessToJobObject(job.value, process.value)) {
            error = GetLastError();
            stop();
            throw WindowsError(error, "YARA job assignment");
        }
        ResumeThread(thread.value);
        metadata = response({}, 30);
        if (metadata.value("status", std::string{}) != "ready") {
            auto message = metadata.dump();
            stop();
            throw std::runtime_error("YARA worker initialization: " + message);
        }
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION actualCpu{};
        if (!QueryInformationJobObject(job.value, JobObjectCpuRateControlInformation, &actualCpu,
                                       sizeof(actualCpu), nullptr))
            throw WindowsError(GetLastError(), "YARA CPU budget verification");
        metadata["job_cpu_percent"] = actualCpu.CpuRate / 100;
        metadata["job_memory_mib"] = 1024;
        metadata["job_process_limit"] = 1;
    }
};
YaraScanner::YaraScanner(const std::string &r, int t, std::uint64_t m, int cpu)
    : impl_(std::make_unique<Impl>(r, t, m, cpu)) {
    impl_->start();
}
YaraScanner::~YaraScanner() = default;
Json YaraScanner::scan(const std::string &path, std::stop_token token) {
    auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    try {
        if (!p.process.value)
            p.start();
        send(p.input.value, {{"path", path}, {"max_bytes", p.maxBytes}, {"timeout_seconds", p.timeout}});
        return p.response(token, p.timeout);
    } catch (const std::exception &e) {
        p.stop();
        return {{"status", "error"}, {"reason", e.what()}, {"matches", Json::array()}};
    }
}
void YaraScanner::reload() {
    auto &p = *impl_;
    std::lock_guard lock(p.mutex);
    auto replacement = std::make_unique<Impl>(p.approved, p.timeout, p.maxBytes, p.maxCpuPercent);
    replacement->start();
    p.stop();
    p.process = std::move(replacement->process);
    p.job = std::move(replacement->job);
    p.input = std::move(replacement->input);
    p.output = std::move(replacement->output);
    p.metadata = replacement->metadata;
}
Json YaraScanner::health() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->metadata;
}
int yaraWorker(const std::string &dir) {
    auto output = GetStdHandle(STD_OUTPUT_HANDLE);
    try {
        Program program(dir);
        send(output, {{"status", "ready"},
                      {"rule_count", program.api.yrx_rules_count(program.rules)},
                      {"pack", program.pack},
                      {"engine", "YARA-X 1.21.0"}});
        for (;;) {
            auto input = receive(GetStdHandle(STD_INPUT_HANDLE));
            try {
                send(output, program.scan(input));
            } catch (const std::exception &e) {
                send(output, {{"status", "error"}, {"reason", e.what()}, {"matches", Json::array()}});
            }
        }
    } catch (const std::exception &e) {
        try {
            send(output, {{"status", "error"}, {"reason", e.what()}});
        } catch (...) {
        }
        return 2;
    }
}
#else
struct YaraScanner::Impl {};
YaraScanner::YaraScanner(const std::string &, int, std::uint64_t, int) {
    throw std::runtime_error("YARA worker implementation requires Windows");
}
YaraScanner::~YaraScanner() = default;
Json YaraScanner::scan(const std::string &, std::stop_token) { return {{"status", "unsupported"}}; }
void YaraScanner::reload() {}
Json YaraScanner::health() const { return {{"status", "unsupported"}}; }
int yaraWorker(const std::string &) { return 2; }
#endif
} // namespace irforge
