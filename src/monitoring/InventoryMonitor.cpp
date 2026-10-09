#include "irforge/monitoring/InventoryMonitor.hpp"
#include "irforge/enrichment/HashEngine.hpp"
#include "irforge/monitoring/Win32.hpp"
#include <set>
#include <thread>
#ifdef _WIN32
#include <iphlpapi.h>
#include <shlguid.h>
#include <shobjidl.h>
#include <taskschd.h>
#include <tinyxml2.h>
#include <tlhelp32.h>
#include <ws2tcpip.h>
#endif
namespace irforge {
std::vector<SecurityEvent> diffInventory(const std::string &kind, const InventoryEntries &before,
                                         const InventoryEntries &after, bool initial, Millis now) {
    const std::map<std::string, std::array<EventType, 3>> types = {
        {"task",
         {EventType::ScheduledTaskAdded, EventType::ScheduledTaskChanged, EventType::ScheduledTaskRemoved}},
        {"service", {EventType::ServiceCreated, EventType::ServiceChanged, EventType::ServiceRemoved}},
        {"startup",
         {EventType::StartupEntryAdded, EventType::StartupEntryChanged, EventType::StartupEntryRemoved}},
        {"registry_inventory",
         {EventType::StartupEntryAdded, EventType::StartupEntryChanged, EventType::StartupEntryRemoved}}};
    auto found = types.find(kind);
    if (found == types.end())
        throw std::runtime_error("invalid inventory kind");
    std::vector<SecurityEvent> events;
    auto emit = [&](const std::string &key, const Json &old, const Json &value, int index) {
        SecurityEvent e;
        e.type = found->second[index];
        e.source = kind + "_inventory";
        e.schemaVersion = 2;
        e.timestampUtc = now;
        e.attributionMethod = "snapshot_difference_actor_unknown";
        e.missingData = {"writer"};
        e.payload = InventoryPayload{kind, key,   index == 0 ? "added" : index == 1 ? "changed" : "removed",
                                     old,  value, initial};
        events.push_back(std::move(e));
    };
    for (auto &[key, value] : after) {
        auto old = before.find(key);
        if (initial || old == before.end())
            emit(key, nullptr, value, 0);
        else if (old->second != value)
            emit(key, old->second, value, 1);
    }
    if (!initial)
        for (auto &[key, value] : before)
            if (!after.contains(key))
                emit(key, value, nullptr, 2);
    return events;
}
#ifdef _WIN32
namespace {
struct ScHandle {
    SC_HANDLE h{};
    explicit ScHandle(SC_HANDLE p) : h(p) {}
    ~ScHandle() {
        if (h)
            CloseServiceHandle(h);
    }
    ScHandle(const ScHandle &) = delete;
};
template <class T> struct Com {
    T *p{};
    ~Com() {
        if (p)
            p->Release();
    }
    T **out() { return &p; }
    T *operator->() { return p; }
    operator bool() const { return p != nullptr; }
};
struct Apartment {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    ~Apartment() {
        if (SUCCEEDED(hr))
            CoUninitialize();
    }
};
struct Bstr {
    BSTR p{};
    Bstr() = default;
    explicit Bstr(const wchar_t *s) : p(SysAllocString(s)) {}
    ~Bstr() { SysFreeString(p); }
    BSTR *out() { return &p; }
    std::string text() const { return p ? utf8(std::wstring(p, SysStringLen(p))) : ""; }
};
std::string pathText(const std::filesystem::path &p) {
    auto s = p.u8string();
    return {s.begin(), s.end()};
}
void fail(InventoryResult &r, const std::string &why) {
    r.complete = false;
    r.gaps.push_back(why);
}
void tasks(ITaskFolder *folder, InventoryResult &r, int depth) {
    if (depth > 16 || r.entries.size() > 10000) {
        fail(r, "Task enumeration budget exceeded");
        return;
    }
    Com<IRegisteredTaskCollection> collection;
    auto hr = folder->GetTasks(TASK_ENUM_HIDDEN, collection.out());
    if (FAILED(hr)) {
        fail(r, "Task folder access: " + std::to_string(hr));
        return;
    }
    LONG count = 0;
    collection->get_Count(&count);
    if (count > 10000) {
        fail(r, "Task count limit");
        return;
    }
    for (LONG index = 1; index <= count; ++index) {
        VARIANT v{};
        VariantInit(&v);
        v.vt = VT_I4;
        v.lVal = index;
        Com<IRegisteredTask> task;
        if (FAILED(collection->get_Item(v, task.out()))) {
            fail(r, "Task item unavailable");
            continue;
        }
        Bstr name, xml;
        TASK_STATE state{};
        VARIANT_BOOL enabled{};
        task->get_Path(name.out());
        task->get_State(&state);
        task->get_Enabled(&enabled);
        Json item = {{"path", name.text()},
                     {"enabled", enabled != VARIANT_FALSE},
                     {"actions", Json::array()},
                     {"actor_pid", nullptr}};
        if (SUCCEEDED(task->get_Xml(xml.out()))) {
            auto text = xml.text();
            tinyxml2::XMLDocument doc;
            if (text.size() > 262144 || doc.Parse(text.data(), text.size()) != tinyxml2::XML_SUCCESS) {
                fail(r, "Task XML invalid/too large");
                continue;
            }
            if (auto root = doc.RootElement())
                if (auto actions = root->FirstChildElement("Actions"))
                    for (auto action = actions->FirstChildElement(); action;
                         action = action->NextSiblingElement()) {
                        Json a = {{"type", action->Name()}, {"arguments", "[redacted]"}};
                        if (auto command = action->FirstChildElement("Command"))
                            if (command->GetText())
                                a["command"] = command->GetText();
                        if (auto directory = action->FirstChildElement("WorkingDirectory"))
                            if (directory->GetText())
                                a["working_directory"] = directory->GetText();
                        item["actions"].push_back(a);
                    }
            // Preserve a hash of task definition to detect edits without persisting
            // sensitive action arguments/XML. Hash is not proof of execution.
            item["definition_sha256"] =
                sha256Bytes(std::span(reinterpret_cast<const std::uint8_t *>(text.data()), text.size()));
        } else {
            fail(r, "Task XML denied: " + name.text());
            continue;
        }
        r.entries[lower(name.text())] = std::move(item);
    }
    Com<ITaskFolderCollection> folders;
    if (FAILED(folder->GetFolders(0, folders.out()))) {
        fail(r, "Task subfolders unavailable");
        return;
    }
    LONG folderCount = 0;
    folders->get_Count(&folderCount);
    if (folderCount > 5000) {
        fail(r, "Task folder count limit");
        return;
    }
    for (LONG i = 1; i <= folderCount; ++i) {
        VARIANT v{};
        v.vt = VT_I4;
        v.lVal = i;
        Com<ITaskFolder> child;
        if (SUCCEEDED(folders->get_Item(v, child.out())))
            tasks(child.p, r, depth + 1);
        else
            fail(r, "Task subfolder denied");
    }
}
} // namespace
InventoryResult inventoryServices() {
    InventoryResult r;
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE));
    if (!scm.h) {
        fail(r, "SCM access: " + std::to_string(GetLastError()));
        return r;
    }
    DWORD needed = 0, count = 0, resume = 0;
    std::vector<std::uint8_t> buffer(256 * 1024);
    do {
        BOOL ok = EnumServicesStatusExW(scm.h, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                        buffer.data(), static_cast<DWORD>(buffer.size()), &needed, &count,
                                        &resume, nullptr);
        DWORD error = ok ? 0 : GetLastError();
        if (error && error != ERROR_MORE_DATA) {
            fail(r, "EnumServicesStatusEx: " + std::to_string(error));
            break;
        }
        auto rows = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW *>(buffer.data());
        for (DWORD i = 0; i < count; ++i) {
            auto name = utf8(rows[i].lpServiceName);
            ScHandle service(OpenServiceW(scm.h, rows[i].lpServiceName, SERVICE_QUERY_CONFIG));
            if (!service.h) {
                fail(r, "Service configuration denied: " + name);
                continue;
            }
            DWORD n = 0;
            QueryServiceConfigW(service.h, nullptr, 0, &n);
            if (!n || n > 65536) {
                fail(r, "Service configuration buffer limit");
                continue;
            }
            std::vector<std::uint8_t> config(n);
            auto q = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(config.data());
            if (!QueryServiceConfigW(service.h, q, n, &n)) {
                fail(r, "Service configuration failed: " + name);
                continue;
            }
            std::string command = utf8(q->lpBinaryPathName);
            try {
                command = expandWindowsPath(command);
            } catch (...) {
            }
            auto image = executablePath(command);
            r.entries[lower(name)] = {{"name", name},
                                      {"display_name", utf8(rows[i].lpDisplayName)},
                                      {"service_type", q->dwServiceType},
                                      {"start_type", q->dwStartType},
                                      {"image", image ? Json(*image) : Json(nullptr)},
                                      {"command_redacted", true},
                                      {"actor_pid", nullptr}};
        }
        if (ok)
            break;
    } while (resume);
    return r;
}
InventoryResult inventoryTasks() {
    InventoryResult r;
    Apartment apartment;
    if (FAILED(apartment.hr) && apartment.hr != RPC_E_CHANGED_MODE) {
        fail(r, "COM initialization failed");
        return r;
    }
    Com<ITaskService> service;
    auto hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService,
                               reinterpret_cast<void **>(service.out()));
    if (FAILED(hr)) {
        fail(r, "Task Scheduler unavailable: " + std::to_string(hr));
        return r;
    }
    VARIANT empty{};
    VariantInit(&empty);
    hr = service->Connect(empty, empty, empty, empty);
    if (FAILED(hr)) {
        fail(r, "Task Scheduler connection failed: " + std::to_string(hr));
        return r;
    }
    Com<ITaskFolder> folder;
    Bstr root(L"\\");
    hr = service->GetFolder(root.p, folder.out());
    if (FAILED(hr)) {
        fail(r, "Task root unavailable");
        return r;
    }
    tasks(folder.p, r, 0);
    return r;
}
InventoryResult inventoryStartup() {
    InventoryResult r;
    Apartment apartment;
    for (auto &known : {"known:Startup", "known:CommonStartup"}) {
        std::string root;
        try {
            root = expandWindowsPath(known);
        } catch (const std::exception &e) {
            fail(r, e.what());
            continue;
        }
        std::error_code ec;
        if (!std::filesystem::exists(filesystemPath(root), ec))
            continue;
        std::filesystem::directory_iterator iterator(
            filesystemPath(root), std::filesystem::directory_options::skip_permission_denied, ec);
        if (ec) {
            fail(r, "Startup directory denied: " + root);
            continue;
        }
        for (auto &entry : iterator) {
            if (r.entries.size() > 10000) {
                fail(r, "Startup entry limit");
                break;
            }
            if (entry.is_directory(ec))
                continue;
            auto path = pathText(entry.path());
            if (!pathWithinRoot(path, root)) {
                fail(r, "Startup reparse boundary excluded");
                continue;
            }
            Json item = {{"path", path}, {"kind", known}, {"actor_pid", nullptr}, {"target", nullptr}};
            if (lower(entry.path().extension().string()) == ".lnk") {
                Com<IShellLinkW> link;
                HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                              reinterpret_cast<void **>(link.out()));
                if (SUCCEEDED(hr)) {
                    Com<IPersistFile> persist;
                    if (SUCCEEDED(link->QueryInterface(IID_IPersistFile,
                                                       reinterpret_cast<void **>(persist.out()))) &&
                        SUCCEEDED(persist->Load(entry.path().c_str(), STGM_READ))) {
                        wchar_t target[32768]{};
                        WIN32_FIND_DATAW data{};
                        if (SUCCEEDED(link->GetPath(target, 32768, &data, SLGP_RAWPATH)))
                            item["target"] = utf8(target);
                    }
                }
            }
            auto hash = hashFile(path, 1024 * 1024);
            item["sha256"] = hash.status == "complete" ? Json(hash.sha256) : Json(nullptr);
            item["hash_status"] = hash.status;
            r.entries[normalizePath(path)] = item;
        }
    }
    return r;
}
InventoryResult inventoryExtendedRegistry() {
    InventoryResult r;
    struct Target {
        HKEY hive;
        const wchar_t *path;
        bool children;
    };
    const Target targets[] = {
        {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", false},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", false},
        {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", false},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", false},
        {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", false},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", false},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
         true}};
    for (auto &target : targets)
        for (REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
            Key key;
            auto code = RegOpenKeyExW(target.hive, target.path, 0,
                                      KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | view, &key.value);
            if (code == ERROR_FILE_NOT_FOUND)
                continue;
            if (code) {
                fail(r, "Registry inventory access: " + std::to_string(code));
                continue;
            }
            auto read = [&](HKEY h, const std::wstring &path, bool debugger) {
                for (DWORD i = 0; i < 10000; ++i) {
                    wchar_t name[16384]{};
                    DWORD nameSize = 16384, type = 0, bytes = 65536;
                    std::vector<std::uint8_t> data(bytes);
                    auto err = RegEnumValueW(h, i, name, &nameSize, nullptr, &type, data.data(), &bytes);
                    if (err == ERROR_NO_MORE_ITEMS)
                        break;
                    if (err) {
                        fail(r, "Registry value inventory error: " + std::to_string(err));
                        continue;
                    }
                    auto valueName = utf8(std::wstring(name, nameSize));
                    if (debugger && lower(valueName) != "debugger")
                        continue;
                    if (!debugger && path.find(L"Winlogon") != std::wstring::npos &&
                        lower(valueName) != "shell" && lower(valueName) != "userinit")
                        continue;
                    std::string text;
                    if ((type == REG_SZ || type == REG_EXPAND_SZ) && bytes % 2 == 0) {
                        std::wstring w(bytes / 2, L'\0');
                        std::memcpy(w.data(), data.data(), bytes);
                        while (!w.empty() && w.back() == L'\0')
                            w.pop_back();
                        text = utf8(w);
                    }
                    auto id = std::string(target.hive == HKEY_LOCAL_MACHINE ? "HKLM\\" : "HKCU\\") +
                              utf8(path) + "\\" + valueName + "@" + (view == KEY_WOW64_64KEY ? "64" : "32");
                    r.entries[lower(id)] = {{"path", id},
                                            {"value_name", valueName},
                                            {"type", type},
                                            {"data", text},
                                            {"actor_pid", nullptr}};
                }
            };
            if (!target.children)
                read(key.value, target.path, false);
            else
                for (DWORD i = 0; i < 10000; ++i) {
                    wchar_t name[256]{};
                    DWORD n = 256;
                    auto err = RegEnumKeyExW(key.value, i, name, &n, nullptr, nullptr, nullptr, nullptr);
                    if (err == ERROR_NO_MORE_ITEMS)
                        break;
                    if (err) {
                        fail(r, "IFEO enumeration error");
                        break;
                    }
                    Key child;
                    if (RegOpenKeyExW(key.value, name, 0, KEY_QUERY_VALUE | view, &child.value) ==
                        ERROR_SUCCESS)
                        read(child.value, std::wstring(target.path) + L"\\" + name, true);
                }
        }
    return r;
}
Json inventoryProcesses() {
    Json rows = Json::array();
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.value == INVALID_HANDLE_VALUE)
        return {{"status", "unavailable"}, {"windows_error", GetLastError()}, {"rows", rows}};
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot.value, &entry))
        do {
            ProcessPayload p;
            p.identity.pid = entry.th32ProcessID;
            p.identity.creationTime100ns = processCreation(entry.th32ProcessID);
            p.parentPid = entry.th32ParentProcessID;
            p.imagePath = utf8(entry.szExeFile);
            p.initialEnumeration = true;
            SecurityEvent e;
            e.type = EventType::ProcessStart;
            e.timestampUtc = utcNow();
            e.payload = p;
            enrichProcess(e);
            rows.push_back(Json(e)["payload"]);
        } while (Process32NextW(snapshot.value, &entry));
    return {{"status", "snapshot"}, {"rows", rows}, {"parent_pid_is_time_unverified", true}};
}
Json inventorySockets() {
    Json rows = Json::array(), gaps = Json::array();
    for (int family : {AF_INET, AF_INET6}) {
        ULONG size = 0;
        auto code = GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (code != ERROR_INSUFFICIENT_BUFFER || size > 32 * 1024 * 1024) {
            gaps.push_back(code);
            continue;
        }
        std::vector<std::uint8_t> data(size);
        code = GetExtendedTcpTable(data.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (code) {
            gaps.push_back(code);
            continue;
        }
        auto address = [&](const void *p) {
            char text[64]{};
            return InetNtopA(family, const_cast<void *>(p), text, 64) ? std::string(text)
                                                                      : std::string("unknown");
        };
        if (family == AF_INET) {
            auto table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID *>(data.data());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                auto &v = table->table[i];
                rows.push_back({{"protocol", "tcp4"},
                                {"owner_pid", v.dwOwningPid},
                                {"local_address", address(&v.dwLocalAddr)},
                                {"local_port", ntohs(static_cast<u_short>(v.dwLocalPort))},
                                {"remote_address", address(&v.dwRemoteAddr)},
                                {"remote_port", ntohs(static_cast<u_short>(v.dwRemotePort))},
                                {"state_code", v.dwState},
                                {"initial_snapshot", true}});
            }
        } else {
            auto table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID *>(data.data());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                auto &v = table->table[i];
                rows.push_back({{"protocol", "tcp6"},
                                {"owner_pid", v.dwOwningPid},
                                {"local_address", address(v.ucLocalAddr)},
                                {"local_scope", v.dwLocalScopeId},
                                {"local_port", ntohs(static_cast<u_short>(v.dwLocalPort))},
                                {"remote_address", address(v.ucRemoteAddr)},
                                {"remote_scope", v.dwRemoteScopeId},
                                {"remote_port", ntohs(static_cast<u_short>(v.dwRemotePort))},
                                {"state_code", v.dwState},
                                {"initial_snapshot", true}});
            }
        }
    }
    return {{"status", gaps.empty() ? "snapshot" : "partial"},
            {"rows", rows},
            {"gaps", gaps},
            {"direction", "unknown"}};
}
struct InventoryMonitor::Impl {
    EventBus &bus;
    Config config;
    std::jthread worker;
    std::map<std::string, InventoryEntries> prior;
    std::set<std::string> initialized;
    Impl(EventBus &b, Config c) : bus(b), config(std::move(c)) {}
    bool scan(const std::string &kind, InventoryResult result) {
        if (!result.complete) {
            std::string gaps;
            for (auto &s : result.gaps) {
                gaps += s + "; ";
                if (gaps.size() > 4096)
                    break;
            }
            monitorStatus(bus, kind + "_inventory", "degraded", gaps);
            // Preserve unavailable entries; partial enumeration cannot prove removal.
            auto combined = prior[kind];
            for (auto &[key, value] : result.entries)
                combined[key] = value;
            result.entries = std::move(combined);
        }
        for (auto &e :
             diffInventory(kind, prior[kind], result.entries, !initialized.contains(kind), utcNow()))
            bus.publish(std::move(e));
        prior[kind] = std::move(result.entries);
        initialized.insert(kind);
        if (result.complete)
            monitorStatus(bus, kind + "_inventory", "active", "Read-only inventory and diff; actor unknown");
        return result.complete;
    }
};
InventoryMonitor::InventoryMonitor(EventBus &b, const Config &c) : impl_(std::make_unique<Impl>(b, c)) {}
InventoryMonitor::~InventoryMonitor() { stop(); }
void InventoryMonitor::start() {
    auto &p = *impl_;
    p.worker = std::jthread([&p](std::stop_token stop) {
        while (!stop.stop_requested()) {
            try {
                bool complete = true;
                if (p.config.watch_scm)
                    complete = p.scan("service", inventoryServices()) && complete;
                if (p.config.watch_tasks)
                    complete = p.scan("task", inventoryTasks()) && complete;
                if (p.config.watch_startup)
                    complete = p.scan("startup", inventoryStartup()) && complete;
                complete = p.scan("registry_inventory", inventoryExtendedRegistry()) && complete;
                monitorStatus(p.bus, "inventory", complete ? "active" : "degraded",
                              complete ? "Selected read-only inventories completed; actor unknown"
                                       : "One or more inventories partial; see per-source health");
            } catch (const std::exception &e) {
                monitorStatus(p.bus, "inventory", "degraded", e.what());
            }
            for (int n = 0; n < p.config.inventory_poll_seconds * 10 && !stop.stop_requested(); ++n)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
}
void InventoryMonitor::stop() noexcept {
    if (impl_ && impl_->worker.joinable()) {
        impl_->worker.request_stop();
        impl_->worker.join();
    }
}
#endif
} // namespace irforge
