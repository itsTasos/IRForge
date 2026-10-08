#include "irforge/monitoring/Diff.hpp"
#include "irforge/monitoring/IMonitor.hpp"
#include "irforge/monitoring/Win32.hpp"
#include <iphlpapi.h>
#include <map>
#include <thread>
#include <ws2tcpip.h>
namespace irforge {
namespace {
std::string stateName(DWORD s) {
    static const char *states[] = {"UNKNOWN",     "CLOSED",     "LISTEN",     "SYN_SENT",   "SYN_RECEIVED",
                                   "ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT", "CLOSING",
                                   "LAST_ACK",    "TIME_WAIT",  "DELETE_TCB"};
    return s < 13 ? states[s] : "UNKNOWN";
}
std::vector<BYTE> table(ULONG family) {
    DWORD size = 0;
    auto code = GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
    if (code != ERROR_INSUFFICIENT_BUFFER && code != NO_ERROR)
        winCheck(code, "GetExtendedTcpTable size");
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (size < sizeof(DWORD) || size > 32 * 1024 * 1024)
            throw std::runtime_error("TCP table size outside bound");
        std::vector<BYTE> buffer(size);
        code = GetExtendedTcpTable(buffer.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (code == ERROR_INSUFFICIENT_BUFFER)
            continue;
        winCheck(code, "GetExtendedTcpTable");
        return buffer;
    }
    throw std::runtime_error("TCP table kept growing across 5 attempts");
}
std::string address(ULONG family, const void *ptr, DWORD scope = 0) {
    char text[INET6_ADDRSTRLEN]{};
    if (!InetNtopA(static_cast<int>(family), const_cast<void *>(ptr), text, sizeof(text)))
        throw std::runtime_error("InetNtopA failed");
    std::string s = text;
    if (scope)
        s += "%" + std::to_string(scope);
    return s;
}
std::vector<TcpPayload> snapshot(Millis observedAt) {
    std::vector<TcpPayload> rows;
    std::map<ProcessId, std::optional<std::uint64_t>> creations;
    auto creation = [&](ProcessId pid) {
        auto it = creations.find(pid);
        if (it == creations.end()) {
            auto value = processCreation(pid);
            if (value && static_cast<Millis>((*value - 116444736000000000ULL) / 10000) > observedAt)
                value.reset();
            it = creations.emplace(pid, value).first;
        }
        return it->second;
    };
    auto v4 = table(AF_INET);
    auto t4 = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID *>(v4.data());
    if (t4->dwNumEntries >
        (v4.size() - offsetof(MIB_TCPTABLE_OWNER_PID, table)) / sizeof(MIB_TCPROW_OWNER_PID))
        throw std::runtime_error("invalid IPv4 TCP table count");
    for (DWORD i = 0; i < t4->dwNumEntries; ++i) {
        const auto &r = t4->table[i];
        TcpPayload p;
        p.ownerPid = r.dwOwningPid;
        p.ownerCreationTime100ns = creation(p.ownerPid);
        p.protocol = "tcp4";
        p.localAddress = address(AF_INET, &r.dwLocalAddr);
        p.remoteAddress = address(AF_INET, &r.dwRemoteAddr);
        p.localPort = ntohs(static_cast<u_short>(r.dwLocalPort));
        p.remotePort = ntohs(static_cast<u_short>(r.dwRemotePort));
        p.state = stateName(r.dwState);
        rows.push_back(std::move(p));
    }
    auto v6 = table(AF_INET6);
    auto t6 = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID *>(v6.data());
    if (t6->dwNumEntries >
        (v6.size() - offsetof(MIB_TCP6TABLE_OWNER_PID, table)) / sizeof(MIB_TCP6ROW_OWNER_PID))
        throw std::runtime_error("invalid IPv6 TCP table count");
    for (DWORD i = 0; i < t6->dwNumEntries; ++i) {
        const auto &r = t6->table[i];
        TcpPayload p;
        p.ownerPid = r.dwOwningPid;
        p.ownerCreationTime100ns = creation(p.ownerPid);
        p.protocol = "tcp6";
        p.localAddress = address(AF_INET6, r.ucLocalAddr, r.dwLocalScopeId);
        p.remoteAddress = address(AF_INET6, r.ucRemoteAddr, r.dwRemoteScopeId);
        p.localPort = ntohs(static_cast<u_short>(r.dwLocalPort));
        p.remotePort = ntohs(static_cast<u_short>(r.dwRemotePort));
        p.state = stateName(r.dwState);
        rows.push_back(std::move(p));
    }
    return rows;
}
} // namespace
struct NetworkMonitor::Impl {
    EventBus &bus;
    Config config;
    NetworkDiff diff;
    std::jthread worker;
    Handle stopEvent{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    bool winsock = false;
    Impl(EventBus &b, const Config &c) : bus(b), config(c) {
        if (!stopEvent.value)
            winCheck(GetLastError(), "network stop event");
    }
    void poll() {
        auto observedAt = utcNow();
        auto rows = snapshot(observedAt);
        for (auto &e : diff.update(rows, observedAt))
            bus.publish(std::move(e));
    }
    void start() {
        WSADATA data{};
        winCheck(static_cast<DWORD>(WSAStartup(MAKEWORD(2, 2), &data)), "WSAStartup");
        winsock = true;
        poll();
        monitorStatus(
            bus, "network", "active",
            "IPv4/IPv6 TCP owner PID snapshot polling; direction and between-poll sessions are unknown.");
        worker = std::jthread([this] {
            while (WaitForSingleObject(stopEvent.value, static_cast<DWORD>(config.network_poll_ms)) ==
                   WAIT_TIMEOUT) {
                try {
                    poll();
                    monitorStatus(bus, "network", "active", "TCP snapshot succeeded");
                } catch (const std::exception &ex) {
                    auto win = dynamic_cast<const WindowsError *>(&ex);
                    monitorStatus(bus, "network", "degraded", ex.what(), win ? win->code : 0);
                }
            }
        });
    }
    void stop() noexcept {
        SetEvent(stopEvent.value);
        if (worker.joinable())
            worker.join();
        if (winsock) {
            WSACleanup();
            winsock = false;
        }
    }
};
NetworkMonitor::NetworkMonitor(EventBus &b, const Config &c) : impl_(std::make_unique<Impl>(b, c)) {}
NetworkMonitor::~NetworkMonitor() { stop(); }
void NetworkMonitor::start() { impl_->start(); }
void NetworkMonitor::stop() noexcept { impl_->stop(); }
} // namespace irforge
