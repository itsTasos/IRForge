#include "irforge/monitoring/IMonitor.hpp"
#include "irforge/monitoring/Win32.hpp"
#include <atomic>
#include <cstring>
#include <evntcons.h>
#include <evntrace.h>
#include <objbase.h>
#include <tdh.h>
#include <thread>
namespace irforge {
namespace {
#ifdef __MINGW32__
// MinGW's tdh.h omits TDH_IN_TYPE; these are the documented schema type IDs, not payload offsets.
constexpr USHORT TDH_INTYPE_UNICODESTRING = 1;
constexpr USHORT TDH_INTYPE_ANSISTRING = 2;
#endif
constexpr GUID processGuid = {0x3d6fa8d0, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
std::optional<std::vector<BYTE>> property(EVENT_RECORD *event, const wchar_t *name) {
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
    descriptor.ArrayIndex = ULONG_MAX;
    ULONG size = 0;
    if (TdhGetPropertySize(event, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS)
        return {};
    if (size > 65536)
        throw std::runtime_error("TDH property exceeds limit");
    std::vector<BYTE> bytes(size);
    if (TdhGetProperty(event, 0, nullptr, 1, &descriptor, size, bytes.data()) != ERROR_SUCCESS)
        return {};
    return bytes;
}
std::optional<DWORD> number(EVENT_RECORD *e, const wchar_t *name) {
    auto bytes = property(e, name);
    if (!bytes || bytes->size() != sizeof(DWORD))
        return {};
    DWORD v = 0;
    std::memcpy(&v, bytes->data(), sizeof(v));
    return v;
}
std::optional<std::string> stringProperty(EVENT_RECORD *event, const wchar_t *name) {
    auto bytes = property(event, name);
    if (!bytes)
        return {};
    ULONG size = 0;
    if (TdhGetEventInformation(event, 0, nullptr, nullptr, &size) != ERROR_INSUFFICIENT_BUFFER ||
        size > 1024 * 1024)
        return {};
    std::vector<BYTE> data(size);
    auto info = reinterpret_cast<TRACE_EVENT_INFO *>(data.data());
    if (TdhGetEventInformation(event, 0, nullptr, info, &size) != ERROR_SUCCESS)
        return {};
    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
        const auto &p = info->EventPropertyInfoArray[i];
        if (p.Flags & PropertyStruct)
            continue;
        auto propName = reinterpret_cast<const wchar_t *>(data.data() + p.NameOffset);
        if (wcscmp(propName, name) != 0)
            continue;
        if (p.nonStructType.InType == TDH_INTYPE_UNICODESTRING) {
            if (bytes->size() % sizeof(wchar_t))
                throw std::runtime_error("invalid TDH UTF-16 length");
            std::wstring w(bytes->size() / sizeof(wchar_t), L'\0');
            if (!bytes->empty())
                std::memcpy(w.data(), bytes->data(), bytes->size());
            auto end = w.find(L'\0');
            if (end != std::wstring::npos)
                w.resize(end);
            return utf8(w);
        }
        if (p.nonStructType.InType == TDH_INTYPE_ANSISTRING) {
            std::string s(bytes->begin(), bytes->end());
            auto end = s.find('\0');
            if (end != std::string::npos)
                s.resize(end);
            if (s.empty())
                return s;
            int n = MultiByteToWideChar(CP_ACP, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
            if (!n)
                return {};
            std::wstring w(static_cast<std::size_t>(n), L'\0');
            MultiByteToWideChar(CP_ACP, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
            return utf8(w);
        }
    }
    return {};
}
} // namespace
struct ProcessMonitor::Impl {
    EventBus &bus;
    Config config;
    TRACEHANDLE session = 0, consumer = INVALID_PROCESSTRACE_HANDLE;
    std::wstring name;
    std::vector<BYTE> properties;
    std::jthread worker, health;
    Handle stopEvent{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::atomic<bool> stopping = false;
    std::atomic<std::uint64_t> decodeErrors{};
    bool owns = false;
    Impl(EventBus &b, const Config &c) : bus(b), config(c) {
        if (!stopEvent.value)
            winCheck(GetLastError(), "ETW stop event");
    }
    EVENT_TRACE_PROPERTIES *props() { return reinterpret_cast<EVENT_TRACE_PROPERTIES *>(properties.data()); }
    static void WINAPI callback(EVENT_RECORD *record) noexcept {
        auto self = static_cast<Impl *>(record->UserContext);
        if (!self || !IsEqualGUID(record->EventHeader.ProviderId, processGuid))
            return;
        auto opcode = record->EventHeader.EventDescriptor.Opcode;
        if (opcode != 1 && opcode != 2 && opcode != 3)
            return;
        try {
            auto pid = number(record, L"ProcessId");
            if (!pid)
                throw std::runtime_error("TDH ProcessId unavailable");
            ProcessPayload p;
            p.identity.pid = *pid;
            p.parentPid = number(record, L"ParentId");
            p.initialEnumeration = opcode == 3;
            p.imagePath = stringProperty(record, L"ImageFileName");
            if (self->config.capture_command_line)
                p.commandLine = stringProperty(record, L"CommandLine");
            if (opcode == 2)
                p.exitCode = number(record, L"ExitStatus");
            SecurityEvent e;
            e.type = opcode == 2 ? EventType::ProcessExit : EventType::ProcessStart;
            e.timestampUtc = (record->EventHeader.TimeStamp.QuadPart - 116444736000000000LL) / 10000;
            e.source = "process_etw";
            e.payload = std::move(p);
            self->bus.publish(std::move(e));
        } catch (...) {
            ++self->decodeErrors;
        }
    }
    void start() {
        GUID guid{};
        auto hr = CoCreateGuid(&guid);
        if (FAILED(hr))
            throw std::runtime_error("CoCreateGuid failed");
        wchar_t text[40]{};
        StringFromGUID2(guid, text, 40);
        name = L"IRForge-" + std::to_wstring(GetCurrentProcessId()) + L"-" + text;
        properties.resize(sizeof(EVENT_TRACE_PROPERTIES) + (name.size() + 1) * sizeof(wchar_t));
        auto p = props();
        p->Wnode.BufferSize = static_cast<ULONG>(properties.size());
        p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        p->Wnode.Guid = guid;
        p->Wnode.ClientContext = 1;
        p->BufferSize = 64;
        p->MinimumBuffers = 4;
        p->MaximumBuffers = 64;
        p->FlushTimer = 1;
        p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        p->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        auto code = StartTraceW(&session, name.c_str(), p);
        if (code != ERROR_SUCCESS)
            throw WindowsError(code, "StartTraceW (run elevated with tracing privileges; check system logger "
                                     "resource limits; no existing session was stopped)");
        owns = true;
        EVENT_TRACE_LOGFILEW log{};
        log.LoggerName = name.data();
        log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        log.EventRecordCallback = &callback;
        log.Context = this;
        consumer = OpenTraceW(&log);
        if (consumer == INVALID_PROCESSTRACE_HANDLE) {
            auto error = GetLastError();
            stop();
            winCheck(error, "OpenTraceW");
        }
        worker = std::jthread([this, handle = consumer]() mutable {
            auto code = ProcessTrace(&handle, 1, nullptr, nullptr);
            if (!stopping)
                monitorStatus(bus, "process_etw", "degraded",
                              "ProcessTrace ended unexpectedly: " + windowsMessage(code), code);
        });
        health = std::jthread([this] {
            while (WaitForSingleObject(stopEvent.value, 5000) == WAIT_TIMEOUT) {
                std::vector<BYTE> query(properties.size());
                auto p = reinterpret_cast<EVENT_TRACE_PROPERTIES *>(query.data());
                p->Wnode.BufferSize = static_cast<ULONG>(query.size());
                p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
                auto code = ControlTraceW(session, name.c_str(), p, EVENT_TRACE_CONTROL_QUERY);
                auto errors = decodeErrors.load();
                if (code == ERROR_SUCCESS)
                    monitorStatus(bus, "process_etw",
                                  p->EventsLost || p->RealTimeBuffersLost || errors ? "degraded" : "active",
                                  "ETW loss counters", 0, p->EventsLost, p->RealTimeBuffersLost, errors);
                else
                    monitorStatus(bus, "process_etw", "degraded", "ETW query: " + windowsMessage(code), code,
                                  0, 0, errors);
            }
        });
        monitorStatus(bus, "process_etw", "active",
                      "Owned real-time SystemTraceProvider session: " + utf8(name));
    }
    void stop() noexcept {
        stopping = true;
        SetEvent(stopEvent.value);
        if (health.joinable())
            health.join();
        if (owns) {
            auto code = ControlTraceW(session, name.c_str(), props(), EVENT_TRACE_CONTROL_STOP);
            if (code != ERROR_SUCCESS && code != ERROR_WMI_INSTANCE_NOT_FOUND) {
                try {
                    monitorStatus(bus, "process_etw", "degraded",
                                  "Could not stop owned session " + utf8(name) + ": " + windowsMessage(code),
                                  code);
                } catch (...) {
                }
            }
            owns = false;
        }
        if (consumer != INVALID_PROCESSTRACE_HANDLE) {
            CloseTrace(consumer);
            consumer = INVALID_PROCESSTRACE_HANDLE;
        }
        if (worker.joinable())
            worker.join();
    }
};
ProcessMonitor::ProcessMonitor(EventBus &b, const Config &c) : impl_(std::make_unique<Impl>(b, c)) {}
ProcessMonitor::~ProcessMonitor() { stop(); }
void ProcessMonitor::start() { impl_->start(); }
void ProcessMonitor::stop() noexcept { impl_->stop(); }
void enrichProcess(SecurityEvent &e) {
    auto p = std::get_if<ProcessPayload>(&e.payload);
    if (!p || e.type != EventType::ProcessStart)
        return;
    Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p->identity.pid));
    if (!h.value)
        return;
    FILETIME c{}, x{}, k{}, u{};
    if (!GetProcessTimes(h.value, &c, &x, &k, &u))
        return;
    auto creation = filetimeValue(c);
    auto creationMs = static_cast<Millis>((creation - 116444736000000000ULL) / 10000);
    if (creationMs > e.timestampUtc)
        return; // PID was already reused after this event.
    p->identity.creationTime100ns = creation;
    std::wstring path(32768, L'\0');
    DWORD size = static_cast<DWORD>(path.size());
    if (QueryFullProcessImageNameW(h.value, 0, path.data(), &size)) {
        path.resize(size);
        p->imagePath = utf8(path);
    }
}
} // namespace irforge
