#pragma once
#ifdef _WIN32
#include "irforge/core/EventBus.hpp"
#include <stdexcept>
#include <utility>
#include <windows.h>
#include <winsock2.h>
namespace irforge {
struct Handle {
    HANDLE value = nullptr;
    Handle() = default;
    explicit Handle(HANDLE v) : value(v) {}
    ~Handle() {
        if (value && value != INVALID_HANDLE_VALUE)
            CloseHandle(value);
    }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    Handle(Handle &&h) noexcept : value(std::exchange(h.value, nullptr)) {}
    Handle &operator=(Handle &&h) noexcept {
        if (this != &h) {
            if (value && value != INVALID_HANDLE_VALUE)
                CloseHandle(value);
            value = std::exchange(h.value, nullptr);
        }
        return *this;
    }
};
struct Key {
    HKEY value = nullptr;
    Key() = default;
    explicit Key(HKEY v) : value(v) {}
    ~Key() {
        if (value)
            RegCloseKey(value);
    }
    Key(const Key &) = delete;
    Key &operator=(const Key &) = delete;
    Key(Key &&h) noexcept : value(std::exchange(h.value, nullptr)) {}
    Key &operator=(Key &&h) noexcept {
        if (this != &h) {
            if (value)
                RegCloseKey(value);
            value = std::exchange(h.value, nullptr);
        }
        return *this;
    }
};
inline std::string windowsMessage(DWORD code) {
    wchar_t *p = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, 0, reinterpret_cast<LPWSTR>(&p), 0, nullptr);
    std::string s = p ? utf8(p) : "Unknown Windows error";
    if (p)
        LocalFree(p);
    return "Windows error " + std::to_string(code) + ": " + s;
}
class WindowsError : public std::runtime_error {
  public:
    DWORD code;
    WindowsError(DWORD c, const std::string &operation)
        : std::runtime_error(operation + ": " + windowsMessage(c)), code(c) {}
};
inline void winCheck(DWORD code, const std::string &operation) {
    if (code != ERROR_SUCCESS)
        throw WindowsError(code, operation);
}
inline std::uint64_t filetimeValue(FILETIME t) {
    return (static_cast<std::uint64_t>(t.dwHighDateTime) << 32) | t.dwLowDateTime;
}
inline std::optional<std::uint64_t> processCreation(ProcessId pid) {
    Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!h.value)
        return {};
    FILETIME c{}, x{}, k{}, u{};
    if (!GetProcessTimes(h.value, &c, &x, &k, &u))
        return {};
    return filetimeValue(c);
}
inline void monitorStatus(EventBus &bus, const std::string &source, const std::string &state,
                          const std::string &message, DWORD code = 0, std::uint64_t lost = 0,
                          std::uint64_t buffers = 0, std::uint64_t decode = 0) {
    SecurityEvent e;
    e.type = EventType::MonitorStatus;
    e.timestampUtc = utcNow();
    e.source = source;
    e.payload = StatusPayload{state, message, code, lost, buffers, decode};
    bus.publish(std::move(e));
}
} // namespace irforge
#endif
