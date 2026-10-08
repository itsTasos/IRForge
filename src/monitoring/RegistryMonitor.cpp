#include "irforge/monitoring/Diff.hpp"
#include "irforge/monitoring/IMonitor.hpp"
#include "irforge/monitoring/Win32.hpp"
#include <algorithm>
#include <thread>
namespace irforge {
namespace {
struct Watch {
    HKEY hive;
    std::string hiveName, path, view;
    REGSAM viewFlag;
    bool services = false, armed = false, dirty = false, unhealthy = false;
    Key parent;
    Handle changed{CreateEventW(nullptr, FALSE, FALSE, nullptr)};
    RegistrySnapshot baseline;
    Millis nextScan{};
};
Key open(HKEY hive, const std::string &path, REGSAM rights) {
    HKEY key = nullptr;
    auto code = RegOpenKeyExW(hive, utf16(path).c_str(), 0, rights, &key);
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
        return {};
    winCheck(static_cast<DWORD>(code), "RegOpenKeyExW " + path);
    return Key(key);
}
void arm(Watch &w) {
    if (w.armed)
        return;
    if (!w.parent.value) {
        auto parent = w.path.substr(0, w.path.find_last_of('\\'));
        while (true) {
            w.parent = open(w.hive, parent, KEY_NOTIFY | w.viewFlag);
            if (w.parent.value)
                break;
            auto n = parent.find_last_of('\\');
            if (n == std::string::npos) {
                w.parent = open(w.hive, "", KEY_NOTIFY | w.viewFlag);
                break;
            }
            parent.resize(n);
        }
    }
    if (!w.parent.value)
        throw std::runtime_error("no accessible existing Registry ancestor for " + w.path);
    auto code = RegNotifyChangeKeyValue(w.parent.value, TRUE,
                                        REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET |
                                            REG_NOTIFY_THREAD_AGNOSTIC,
                                        w.changed.value, TRUE);
    if (code != ERROR_SUCCESS) {
        w.parent = Key{};
        winCheck(static_cast<DWORD>(code), "RegNotifyChangeKeyValue " + w.path);
    }
    w.armed = true;
}
std::map<std::string, RegistryValue> values(HKEY key, bool selectedOnly, std::size_t &total) {
    std::map<std::string, RegistryValue> result;
    for (DWORD index = 0; index < 16384; ++index) {
        std::wstring name(16384, L'\0');
        DWORD nameSize = static_cast<DWORD>(name.size()), type = 0, size = 0;
        auto code = RegEnumValueW(key, index, name.data(), &nameSize, nullptr, &type, nullptr, &size);
        if (code == ERROR_NO_MORE_ITEMS)
            return result;
        winCheck(static_cast<DWORD>(code), "RegEnumValueW size");
        name.resize(nameSize);
        auto text = lower(utf8(name));
        if (selectedOnly && text != "imagepath" && text != "start" && text != "type")
            continue;
        if (size > 65536 || total + size > 32 * 1024 * 1024)
            throw std::runtime_error("Registry snapshot exceeds 64 KiB value / 32 MiB snapshot limit");
        std::vector<BYTE> bytes(size);
        DWORD actual = size;
        code = RegQueryValueExW(key, name.c_str(), nullptr, &type, bytes.data(), &actual);
        winCheck(static_cast<DWORD>(code), "RegQueryValueExW snapshot changed; retry later");
        bytes.resize(actual);
        total += actual;
        result[text] = decodeRegistryValue(type, bytes);
        if (result.size() > 4096)
            throw std::runtime_error("too many watched Registry values");
    }
    throw std::runtime_error("Registry value enumeration limit reached");
}
RegistrySnapshot snapshot(const Watch &w) {
    RegistrySnapshot s;
    auto root = open(w.hive, w.path, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | w.viewFlag);
    if (!root.value)
        return s;
    std::size_t bytes = 0;
    s.keys[w.path] = w.services ? std::map<std::string, RegistryValue>{} : values(root.value, false, bytes);
    if (w.services) {
        for (DWORD index = 0; index < 10000; ++index) {
            wchar_t name[256]{};
            DWORD count = 256;
            auto code = RegEnumKeyExW(root.value, index, name, &count, nullptr, nullptr, nullptr, nullptr);
            if (code == ERROR_NO_MORE_ITEMS)
                return s;
            winCheck(static_cast<DWORD>(code), "RegEnumKeyExW services");
            std::string path = w.path + "\\" + utf8(std::wstring(name, count));
            auto service = open(w.hive, path, KEY_QUERY_VALUE | w.viewFlag);
            if (!service.value)
                throw std::runtime_error(
                    "Service disappeared during snapshot; preserve previous state and retry");
            s.keys[path] = values(service.value, true, bytes);
        }
        throw std::runtime_error("service enumeration exceeds 10000 keys");
    }
    return s;
}
} // namespace
struct RegistryMonitor::Impl {
    EventBus &bus;
    Config config;
    std::vector<Watch> watches;
    std::jthread worker;
    Handle stopEvent{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Impl(EventBus &b, const Config &c) : bus(b), config(c) {
        if (!stopEvent.value)
            winCheck(GetLastError(), "Registry stop event");
    }
    void add(HKEY hive, const char *name, const std::string &path, REGSAM flag, bool services) {
        Watch w;
        w.hive = hive;
        w.hiveName = name;
        w.path = path;
        w.view = flag == KEY_WOW64_32KEY ? "32" : "64";
        w.viewFlag = flag;
        w.services = services;
        if (!w.changed.value)
            winCheck(GetLastError(), "Registry change event");
        arm(w);
        w.baseline = snapshot(w);
        w.nextScan = utcNow() + 5000;
        watches.push_back(std::move(w));
    }
    void start() {
        if (config.watch_run_keys)
            for (auto hive : {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE})
                for (auto view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY})
                    for (const auto *leaf : {"Run", "RunOnce"})
                        add(hive, hive == HKEY_CURRENT_USER ? "HKCU" : "HKLM",
                            std::string("Software\\Microsoft\\Windows\\CurrentVersion\\") + leaf, view,
                            false);
        // SYSTEM is shared across WOW64 views; enumerate it only once.
        if (config.watch_services)
            add(HKEY_LOCAL_MACHINE, "HKLM", "SYSTEM\\CurrentControlSet\\Services", KEY_WOW64_64KEY, true);
        monitorStatus(bus, "registry", "active",
                      "Run/RunOnce views and selected service values baselined. Writer PID unknown. Missing "
                      "keys watched through existing ancestors.");
        worker = std::jthread([this] {
            bool wasDegraded = false;
            while (WaitForSingleObject(stopEvent.value, 100) == WAIT_TIMEOUT) {
                for (auto &w : watches) {
                    try {
                        if (!w.armed && utcNow() < w.nextScan)
                            continue;
                        if (w.armed && WaitForSingleObject(w.changed.value, 0) == WAIT_OBJECT_0) {
                            w.armed = false;
                            arm(w);
                            if (!w.dirty)
                                w.nextScan = utcNow() + 250;
                            w.dirty = true;
                        }
                        if (!w.armed)
                            arm(w);
                        if (utcNow() < w.nextScan)
                            continue;
                        auto current = snapshot(w);
                        for (auto &e : registryDiff(w.baseline, current, w.hiveName, w.view, utcNow()))
                            bus.publish(std::move(e));
                        w.baseline = std::move(current);
                        w.dirty = false;
                        w.nextScan = utcNow() + 5000;
                        w.unhealthy = false;
                    } catch (const std::exception &ex) {
                        w.unhealthy = true;
                        w.nextScan = utcNow() + 5000;
                        auto win = dynamic_cast<const WindowsError *>(&ex);
                        monitorStatus(bus, "registry", "degraded",
                                      w.hiveName + "\\" + w.path + " view=" + w.view + ": " + ex.what(),
                                      win ? win->code : 0);
                    }
                }
                bool degraded =
                    std::any_of(watches.begin(), watches.end(), [](const auto &w) { return w.unhealthy; });
                if (wasDegraded && !degraded)
                    monitorStatus(
                        bus, "registry", "active",
                        "All Registry watches recovered; previous state was preserved during errors.");
                wasDegraded = degraded;
            }
        });
    }
    void stop() noexcept {
        SetEvent(stopEvent.value);
        if (worker.joinable())
            worker.join();
        watches.clear();
    }
};
RegistryMonitor::RegistryMonitor(EventBus &b, const Config &c) : impl_(std::make_unique<Impl>(b, c)) {}
RegistryMonitor::~RegistryMonitor() { stop(); }
void RegistryMonitor::start() { impl_->start(); }
void RegistryMonitor::stop() noexcept { impl_->stop(); }
} // namespace irforge
