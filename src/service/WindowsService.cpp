#include "irforge/service/WindowsService.hpp"
#include "irforge/cli/Commands.hpp"
#include "irforge/core/Config.hpp"
#include "irforge/core/Schema.hpp"
#include "irforge/enrichment/HashEngine.hpp"
#include "irforge/ipc/PipeServer.hpp"
#include "irforge/monitoring/Win32.hpp"
#include "irforge/reporting/Evidence.hpp"
#include <iostream>
#include <set>
#ifdef _WIN32
#include <aclapi.h>
#include <sddl.h>
#endif
namespace irforge {
bool validServiceTransition(const std::string &from, const std::string &to) {
    static const std::set<std::pair<std::string, std::string>> allowed = {
        {"stopped", "start_pending"}, {"start_pending", "running"}, {"start_pending", "stopped"},
        {"running", "stop_pending"},  {"running", "stopped"},       {"stop_pending", "stop_pending"},
        {"stop_pending", "stopped"}};
    return allowed.contains({from, to});
}
#ifdef _WIN32
namespace {
constexpr const wchar_t *serviceName = L"IRForge";
struct ScHandle {
    SC_HANDLE value{};
    explicit ScHandle(SC_HANDLE h) : value(h) {
        if (!h)
            throw WindowsError(GetLastError(), "Service Control Manager");
    }
    ~ScHandle() { CloseServiceHandle(value); }
    ScHandle(const ScHandle &) = delete;
};
std::wstring quote(const std::wstring &input) {
    std::wstring s = L"\"";
    unsigned slashes = 0;
    for (auto c : input) {
        if (c == '\\') {
            ++slashes;
            continue;
        }
        s.append(c == '"' ? 2 * slashes + 1 : slashes, L'\\');
        slashes = 0;
        s += c;
    }
    s.append(slashes * 2, L'\\');
    return s + L'"';
}
std::string executable() {
    wchar_t path[32768]{};
    auto n = GetModuleFileNameW(nullptr, path, 32768);
    if (!n || n == 32768)
        throw WindowsError(GetLastError(), "service executable path");
    return utf8(std::wstring(path, n));
}
void protectedDirectory(const std::string &path) {
    std::filesystem::create_directories(filesystemPath(path));
    PSECURITY_DESCRIPTOR descriptor{};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                                                              SDDL_REVISION_1, &descriptor, nullptr))
        throw WindowsError(GetLastError(), "service directory DACL");
    BOOL present{}, defaulted{};
    PACL acl{};
    GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted);
    auto error = SetNamedSecurityInfoW(const_cast<wchar_t *>(filesystemPath(path).c_str()), SE_FILE_OBJECT,
                                       DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                       nullptr, nullptr, acl, nullptr);
    LocalFree(descriptor);
    winCheck(error, "protect service directory");
}
void protectedExecutable(const std::string &path) {
    auto normalized = normalizePath(path);
    auto programFiles = normalizePath(expandWindowsPath("%ProgramFiles%"));
    if (!normalized.starts_with(programFiles + "\\"))
        throw std::runtime_error("service executable must be installed under protected Program Files; use "
                                 "the installer, then run service install");
    auto candidate = filesystemPath(path);
    for (int depth = 0; depth < 32; ++depth) {
        PSECURITY_DESCRIPTOR descriptor{};
        PACL acl{};
        auto error =
            GetNamedSecurityInfoW(const_cast<wchar_t *>(candidate.c_str()), SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION, nullptr, nullptr, &acl, nullptr, &descriptor);
        if (error != ERROR_SUCCESS)
            throw WindowsError(error, "service executable permissions");
        bool writable = !acl;
        for (DWORD i = 0; acl && i < acl->AceCount; ++i) {
            void *raw{};
            if (!GetAce(acl, i, &raw))
                continue;
            auto header = static_cast<ACE_HEADER *>(raw);
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE)
                continue;
            auto ace = static_cast<ACCESS_ALLOWED_ACE *>(raw);
            LPWSTR sid{};
            if (!ConvertSidToStringSidW(&ace->SidStart, &sid))
                continue;
            auto value = utf8(sid);
            LocalFree(sid);
            if ((value == "S-1-1-0" || value == "S-1-5-11" || value == "S-1-5-32-545") &&
                (ace->Mask & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC |
                              WRITE_OWNER | DELETE)))
                writable = true;
        }
        if (descriptor)
            LocalFree(descriptor);
        if (writable)
            throw std::runtime_error("service binary or parent directory permits unprivileged writes");
        if (normalizePath(candidate.string()) == programFiles)
            return;
        auto parent = candidate.parent_path();
        if (parent == candidate || parent.empty())
            break;
        candidate = parent;
    }
    throw std::runtime_error("service executable path validation exceeded depth");
}
struct Runtime {
    SERVICE_STATUS_HANDLE handle{};
    SERVICE_STATUS status{};
    std::mutex mutex;
    std::stop_source stop;
    ServiceRunner runner;
    std::vector<std::string> arguments;
};
Runtime *runtime{};
void report(DWORD state, DWORD error = 0) {
    auto &r = *runtime;
    std::lock_guard lock(r.mutex);
    auto stateName = [](DWORD s) {
        switch (s) {
        case SERVICE_START_PENDING:
            return "start_pending";
        case SERVICE_RUNNING:
            return "running";
        case SERVICE_STOP_PENDING:
            return "stop_pending";
        default:
            return "stopped";
        }
    };
    if (!validServiceTransition(stateName(r.status.dwCurrentState), stateName(state))) {
        r.stop.request_stop();
        return;
    }
    r.status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    r.status.dwCurrentState = state;
    r.status.dwControlsAccepted =
        state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN
                                 : 0;
    r.status.dwWin32ExitCode = error ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR;
    r.status.dwServiceSpecificExitCode = error;
    r.status.dwWaitHint = (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) ? 15000 : 0;
    r.status.dwCheckPoint =
        (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) ? r.status.dwCheckPoint + 1 : 0;
    if (!SetServiceStatus(r.handle, &r.status))
        r.stop.request_stop();
}
DWORD WINAPI control(DWORD code, DWORD, void *, void *) {
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN ||
        code == SERVICE_CONTROL_PRESHUTDOWN) {
        report(SERVICE_STOP_PENDING);
        runtime->stop.request_stop();
        return NO_ERROR;
    }
    if (code == SERVICE_CONTROL_INTERROGATE) {
        std::lock_guard lock(runtime->mutex);
        SetServiceStatus(runtime->handle, &runtime->status);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}
void WINAPI serviceMain(DWORD, wchar_t **) {
    auto &r = *runtime;
    r.handle = RegisterServiceCtrlHandlerExW(serviceName, control, nullptr);
    if (!r.handle)
        return;
    report(SERVICE_START_PENDING);
    int result = 2;
    try {
        report(SERVICE_RUNNING);
        result = r.runner(r.arguments, r.stop.get_token());
    } catch (...) {
        result = 2;
    }
    report(SERVICE_STOPPED, static_cast<DWORD>(result));
}
Json status() {
    ScHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    auto raw = OpenServiceW(manager.value, serviceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!raw) {
        auto error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST)
            return {{"installed", false}, {"name", "IRForge"}};
        throw WindowsError(error, "query IRForge service");
    }
    ScHandle service(raw);
    SERVICE_STATUS_PROCESS info{};
    DWORD n = 0;
    if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE *>(&info),
                              sizeof(info), &n))
        throw WindowsError(GetLastError(), "service status");
    return {{"installed", true},
            {"name", "IRForge"},
            {"state", info.dwCurrentState},
            {"pid", info.dwProcessId},
            {"exit_code", info.dwWin32ExitCode},
            {"service_specific_exit_code", info.dwServiceSpecificExitCode}};
}
} // namespace
#endif
std::optional<int> serviceCommand(const std::vector<std::string> &args, const ServiceRunner &runner) {
    if (args.size() < 2 || args[1] != "service")
        return {};
    if (args.size() < 3)
        throw std::runtime_error("service requires install/uninstall/start/stop/status/run");
#ifdef _WIN32
    auto action = args[2];
    Arguments options(args, 3, {"--config", "--data-dir", "--rules"}, {"--confirm", "--auto-start"});
    if (action == "status") {
        std::cout << status().dump(2) << '\n';
        return 0;
    }
    if (action == "install") {
        if (!options.has("--confirm"))
            throw std::runtime_error(
                "service install requires --confirm and an elevated administrator token");
        auto exe = executable();
        protectedExecutable(exe);
        auto data = options.get("--data-dir", expandWindowsPath("%ProgramData%\\IRForge"));
        auto dataPath = filesystemPath(data);
        if (!dataPath.is_absolute())
            throw std::runtime_error("service data directory must be absolute");
        if (std::filesystem::exists(dataPath) && !std::filesystem::is_empty(dataPath) &&
            !std::filesystem::exists(dataPath / "IRForge.service-data.json"))
            throw std::runtime_error("service data directory must be new/empty or previously created by "
                                     "IRForge; existing unrelated directories are refused");
        auto config = Config::load(options.require("--config"));
        auto document = config.json();
        for (auto &root : config.file_roots)
            root = expandWindowsPath(root);
        if (document.contains("file_monitor"))
            document["file_monitor"]["roots"] = config.file_roots;
        if (!document.contains("ipc"))
            document["ipc"] = Json::object();
        document["ipc"]["allowed_reader_sids"] = Json::array({currentUserSid()});
        auto rules = options.get("--rules", (filesystemPath(exe).parent_path() / "rules/internal").string());
        rules = std::filesystem::absolute(filesystemPath(rules)).string();
        (void)RuleEngine::load(rules);
        protectedDirectory(data);
        writeDocument(dataPath / "IRForge.service-data.json",
                      {{"application", "IRForge"}, {"purpose", "protected service data"}});
        writeDocument(dataPath / "service-config.json", document);
        auto configPath = (dataPath / "service-config.json").string();
        auto command = quote(utf16(exe)) + L" service run --config " + quote(utf16(configPath)) +
                       L" --data-dir " + quote(utf16(data)) + L" --rules " + quote(utf16(rules));
        ScHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
        ScHandle service(CreateServiceW(
            manager.value, serviceName, L"IRForge Endpoint Evidence Agent",
            SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS, SERVICE_WIN32_OWN_PROCESS,
            options.has("--auto-start") ? SERVICE_AUTO_START : SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr));
        SERVICE_DESCRIPTIONW description{
            const_cast<wchar_t *>(L"Visible read-only endpoint evidence collection and local incident "
                                  L"triage. No remote command execution or remediation.")};
        ChangeServiceConfig2W(service.value, SERVICE_CONFIG_DESCRIPTION, &description);
        SC_ACTION actions[] = {{SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 30000}, {SC_ACTION_NONE, 0}};
        SERVICE_FAILURE_ACTIONSW recovery{86400, nullptr, nullptr, 3, actions};
        ChangeServiceConfig2W(service.value, SERVICE_CONFIG_FAILURE_ACTIONS, &recovery);
        std::cout << "IRForge service installed; collection starts only when the service is started\n";
        return 0;
    }
    if (action == "uninstall" || action == "start" || action == "stop") {
        if (action == "uninstall" && !options.has("--confirm"))
            throw std::runtime_error("service uninstall requires --confirm; evidence remains on disk");
        ScHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        ScHandle service(OpenServiceW(manager.value, serviceName,
                                      SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS |
                                          (action == "uninstall" ? DELETE : 0)));
        if (action == "start") {
            if (!StartServiceW(service.value, 0, nullptr))
                throw WindowsError(GetLastError(), "start IRForge");
            return 0;
        }
        SERVICE_STATUS info{};
        if (!ControlService(service.value, SERVICE_CONTROL_STOP, &info) &&
            GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
            throw WindowsError(GetLastError(), "stop IRForge");
        auto deadline = GetTickCount64() + 20000;
        for (;;) {
            SERVICE_STATUS_PROCESS current{};
            DWORD bytes = 0;
            if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO,
                                      reinterpret_cast<BYTE *>(&current), sizeof(current), &bytes))
                throw WindowsError(GetLastError(), "wait IRForge stop");
            if (current.dwCurrentState == SERVICE_STOPPED)
                break;
            if (GetTickCount64() >= deadline)
                throw std::runtime_error("IRForge stop still pending; service was not deleted");
            Sleep(100);
        }
        if (action == "uninstall" && !DeleteService(service.value))
            throw WindowsError(GetLastError(), "delete IRForge service");
        std::cout << "IRForge " << action << " complete; evidence preserved\n";
        return 0;
    }
    if (action == "run") {
        auto config = options.require("--config"), data = options.require("--data-dir"),
             rules = options.require("--rules");
        Runtime context;
        context.runner = runner;
        auto session = (filesystemPath(data) / "sessions" / newUuid()).string();
        context.arguments = {"irforge",
                             "monitor",
                             "--config",
                             config,
                             "--rules",
                             rules,
                             "--output",
                             session,
                             "--db",
                             (filesystemPath(data) / "irforge.sqlite").string(),
                             "--pipe",
                             Config::load(config).pipe_name,
                             "--allow-degraded",
                             "--quiet"};
        runtime = &context;
        SERVICE_TABLE_ENTRYW table[] = {{const_cast<wchar_t *>(serviceName), serviceMain},
                                        {nullptr, nullptr}};
        bool dispatched = StartServiceCtrlDispatcherW(table) != 0;
        auto error = GetLastError();
        runtime = nullptr;
        if (!dispatched)
            throw WindowsError(error, "service dispatcher (run is SCM-only)");
        return 0;
    }
    throw std::runtime_error("unsupported service action");
#else
    (void)runner;
    throw std::runtime_error("Windows SCM required");
#endif
}
} // namespace irforge
