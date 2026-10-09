#include "irforge/windows/EventLogSubscriber.hpp"
#include "irforge/monitoring/Win32.hpp"
#include <cctype>
#include <charconv>
#include <cstring>
#include <fstream>
#include <set>
#include <tinyxml2.h>
#include <utility>
#ifdef _WIN32
#include <winevt.h>
#endif
namespace irforge {
namespace {
std::uint32_t number(const std::string &s) {
    std::uint32_t result = 0;
    auto parsed = std::from_chars(s.data(), s.data() + s.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != s.data() + s.size())
        throw std::runtime_error("invalid provider integer");
    return result;
}
bool validGuid(const std::string &g) {
    if (g.size() != 38 || g.front() != '{' || g.back() != '}')
        return false;
    for (std::size_t i = 1; i < 37; ++i)
        if (i == 9 || i == 14 || i == 19 || i == 24) {
            if (g[i] != '-')
                return false;
        } else if (!std::isxdigit(static_cast<unsigned char>(g[i])))
            return false;
    return true;
}
std::string element(tinyxml2::XMLElement *parent, const char *name) {
    auto node = parent ? parent->FirstChildElement(name) : nullptr;
    return node && node->GetText() ? node->GetText() : "";
}
std::optional<std::string> text(const ProviderRecord &r, const std::string &key) {
    auto it = r.data.find(key);
    return it == r.data.end() || it->second.empty() || it->second == "-" ? std::optional<std::string>{}
                                                                         : it->second;
}
} // namespace
Millis parseProviderUtc(const std::string &input) {
    auto s = input;
    if (s.size() > 10 && s[10] == ' ')
        s[10] = 'T';
    if (s.empty())
        throw std::runtime_error("provider timestamp missing");
    if (s.back() != 'Z')
        s += 'Z';
    if (s.size() < 20 || s[19] != '.')
        s.insert(19, ".000");
    auto end = s.find('Z', 20);
    if (end == std::string::npos || end != s.size() - 1)
        throw std::runtime_error("provider timestamp must be UTC");
    auto fraction = s.substr(20, end - 20);
    if (fraction.empty() || fraction.size() > 7 ||
        fraction.find_first_not_of("0123456789") != std::string::npos)
        throw std::runtime_error("invalid provider timestamp precision");
    fraction.resize(3, '0');
    return parseUtc(s.substr(0, 20) + fraction + "Z");
}
ProviderRecord parseProviderXml(const std::string &xml) {
    if (xml.size() > 1048576 || xml.find("<!DOCTYPE") != std::string::npos ||
        xml.find("<!ENTITY") != std::string::npos)
        throw std::runtime_error("provider XML size/DTD not allowed");
    tinyxml2::XMLDocument doc;
    if (doc.Parse(xml.data(), xml.size()) != tinyxml2::XML_SUCCESS)
        throw std::runtime_error("malformed provider XML");
    auto root = doc.RootElement();
    if (!root || std::string(root->Name()) != "Event")
        throw std::runtime_error("expected Event XML root");
    auto system = root->FirstChildElement("System");
    if (!system)
        throw std::runtime_error("provider System block missing");
    ProviderRecord r;
    auto provider = system->FirstChildElement("Provider");
    if (!provider || !provider->Attribute("Name"))
        throw std::runtime_error("provider name missing");
    r.provider = provider->Attribute("Name");
    r.eventId = number(element(system, "EventID"));
    r.recordId = element(system, "EventRecordID");
    r.channel = element(system, "Channel");
    r.host = element(system, "Computer");
    auto time = system->FirstChildElement("TimeCreated");
    if (!time || !time->Attribute("SystemTime"))
        throw std::runtime_error("provider time missing");
    r.timestamp = time->Attribute("SystemTime");
    (void)parseProviderUtc(r.timestamp);
    if (!r.recordId.empty()) {
        std::uint64_t value{};
        auto p = std::from_chars(r.recordId.data(), r.recordId.data() + r.recordId.size(), value);
        if (p.ec != std::errc{} || p.ptr != r.recordId.data() + r.recordId.size())
            throw std::runtime_error("invalid record ID");
    }
    if (auto data = root->FirstChildElement("EventData"))
        for (auto field = data->FirstChildElement("Data"); field; field = field->NextSiblingElement("Data")) {
            auto name = field->Attribute("Name");
            if (!name)
                throw std::runtime_error("unnamed provider data unsupported");
            std::string value = field->GetText() ? field->GetText() : "";
            if (r.data.size() >= 256 || std::strlen(name) > 128 || value.size() > 65536 ||
                r.data.contains(name))
                throw std::runtime_error("provider field exceeds limits or duplicates");
            r.data[name] = value;
        }
    return r;
}
std::vector<SecurityEvent> normalizeProviderRecord(const ProviderRecord &r) {
    SecurityEvent e;
    e.schemaVersion = 2;
    e.timestampUtc = parseProviderUtc(r.timestamp);
    e.observedAtUtc = utcNow();
    e.providerChannel = r.channel;
    e.sourceRecordId = r.channel + "/" + r.recordId;
    e.host = r.host;
    e.source = r.provider == "Microsoft-Windows-Sysmon" ? "sysmon" : "windows_eventlog";
    e.attributionMethod = "provider_record";
    e.attributionConfidence = "medium";
    auto process = [&]() {
        ProcessPayload p;
        auto pid = text(r, "ProcessId");
        if (!pid)
            throw std::runtime_error("Sysmon process ID missing");
        p.identity.pid = number(*pid);
        if (auto guid = text(r, "ProcessGuid")) {
            if (!validGuid(*guid))
                throw std::runtime_error("invalid Sysmon ProcessGuid");
            p.identity.processGuid = lower(*guid);
        }
        p.imagePath = text(r, "Image");
        if (auto utc = text(r, "UtcTime"))
            e.timestampUtc = parseProviderUtc(*utc);
        e.attributionMethod = p.identity.processGuid ? "provider_process_guid" : "provider_pid_only";
        e.attributionConfidence = p.identity.processGuid ? "high" : "low";
        return p;
    };
    if (e.source == "sysmon")
        switch (r.eventId) {
        case 1: {
            auto p = process();
            p.commandLine = text(r, "CommandLine");
            if (auto parent = text(r, "ParentProcessId"))
                p.parentPid = number(*parent);
            if (auto guid = text(r, "ParentProcessGuid")) {
                if (!validGuid(*guid))
                    throw std::runtime_error("invalid parent ProcessGuid");
                p.parentProcessGuid = lower(*guid);
            }
            p.parentImagePath = text(r, "ParentImage");
            e.type = EventType::ProcessStart;
            e.payload = p;
            break;
        }
        case 5: {
            e.type = EventType::ProcessExit;
            e.payload = process();
            break;
        }
        case 3: {
            auto p = process();
            TcpPayload n;
            n.ownerPid = p.identity.pid;
            n.ownerProcessGuid = p.identity.processGuid;
            auto protocol = lower(text(r, "Protocol").value_or("unknown"));
            if (protocol != "tcp") {
                e.type = EventType::Unmapped;
                e.payload = ObservationPayload{{{"provider", r.provider},
                                                {"provider_event_id", r.eventId},
                                                {"reason", "non-TCP Sysmon network event"},
                                                {"fields", r.data}}};
                break;
            }
            n.localAddress = text(r, "SourceIp").value_or("");
            n.remoteAddress = text(r, "DestinationIp").value_or("");
            n.protocol = n.remoteAddress.find(':') != std::string::npos ? "tcp6" : "tcp4";
            auto port = [&](const char *key) {
                auto value = text(r, key);
                if (!value)
                    throw std::runtime_error("Sysmon port missing");
                auto v = number(*value);
                if (v > 65535)
                    throw std::runtime_error("invalid Sysmon port");
                return static_cast<std::uint16_t>(v);
            };
            n.localPort = port("SourcePort");
            n.remotePort = port("DestinationPort");
            if (addressClass(n.localAddress) == "invalid" || addressClass(n.remoteAddress) == "invalid")
                throw std::runtime_error("invalid Sysmon IP");
            n.state = "ESTABLISHED";
            n.change = "provider_connect";
            e.type = EventType::SysmonNetworkConnect;
            e.payload = n;
            break;
        }
        case 11: {
            auto p = process();
            e.type = EventType::FileCreated;
            e.payload = FilePayload{text(r, "TargetFilename").value_or(""),
                                    "",
                                    "provider_created",
                                    p.identity.pid,
                                    {{"provider_process_guid",
                                      p.identity.processGuid ? Json(*p.identity.processGuid) : Json(nullptr)},
                                     {"image", p.imagePath ? Json(*p.imagePath) : Json(nullptr)}}};
            break;
        }
        case 12:
        case 13:
        case 14: {
            auto p = process();
            RegistryPayload reg;
            reg.actorPid = p.identity.pid;
            reg.view = "provider_unspecified";
            auto target = text(r, "TargetObject").value_or("");
            auto split = target.find('\\');
            reg.hive = split == std::string::npos ? "unknown" : target.substr(0, split);
            auto path = split == std::string::npos ? target : target.substr(split + 1);
            auto action = text(r, "EventType").value_or("");
            if (action == "CreateKey" || action == "DeleteKey") {
                reg.keyPath = path;
                e.type = action == "CreateKey" ? EventType::RegistryKeyAdded : EventType::RegistryKeyDeleted;
            } else {
                auto last = path.find_last_of('\\');
                reg.keyPath = last == std::string::npos ? path : path.substr(0, last);
                reg.valueName = last == std::string::npos ? "" : path.substr(last + 1);
                if (r.eventId == 13) {
                    RegistryValue value;
                    value.type = 0;
                    value.text = text(r, "Details");
                    reg.newData = value;
                    e.type = EventType::RegistryValueModified;
                } else if (action == "DeleteValue")
                    e.type = EventType::RegistryValueDeleted;
                else if (action == "CreateValue")
                    e.type = EventType::RegistryValueAdded;
                else
                    e.type = EventType::SysmonRegistryChange;
            }
            e.attributionMethod = "sysmon_explicit_registry_actor";
            e.payload = reg;
            e.missingData = {"native_registry_value_type_and_bytes", "prior_registry_value"};
            break;
        }
        case 22: {
            auto p = process();
            e.type = EventType::DnsObserved;
            e.payload = ObservationPayload{{{"process_identity", identityJson(p.identity)},
                                            {"query_name", text(r, "QueryName").value_or("")},
                                            {"query_status", text(r, "QueryStatus").value_or("")},
                                            {"query_results", text(r, "QueryResults").value_or("")}}};
            break;
        }
        default:
            e.type = EventType::Unmapped;
            e.payload = ObservationPayload{
                {{"provider", r.provider}, {"provider_event_id", r.eventId}, {"fields", r.data}}};
            break;
        }
    else if (r.provider == "Microsoft-Windows-Security-Auditing" &&
             (r.eventId == 4624 || r.eventId == 4625)) {
        e.type = EventType::LogonObserved;
        e.payload = ObservationPayload{{{"provider_event_id", r.eventId},
                                        {"result", r.eventId == 4624 ? "success" : "failure"},
                                        {"account", text(r, "TargetUserName").value_or("")},
                                        {"domain", text(r, "TargetDomainName").value_or("")},
                                        {"logon_type", text(r, "LogonType").value_or("")},
                                        {"source_ip", text(r, "IpAddress").value_or("")},
                                        {"audit_policy_coverage", "not_inferred"}}};
    } else if (r.provider == "Service Control Manager" && r.eventId == 7045) {
        e.type = EventType::ServiceCreated;
        e.payload = InventoryPayload{"service",
                                     text(r, "ServiceName").value_or("unknown"),
                                     "provider_install",
                                     nullptr,
                                     {{"name", text(r, "ServiceName").value_or("")},
                                      {"image", text(r, "ImagePath").value_or("")},
                                      {"start_type", text(r, "StartType").value_or("")},
                                      {"actor_pid", nullptr}},
                                     false};
    } else {
        e.type = EventType::Unmapped;
        e.payload = ObservationPayload{
            {{"provider", r.provider}, {"provider_event_id", r.eventId}, {"fields", r.data}}};
    }
    return {e};
}
#ifdef _WIN32
namespace {
struct Evt {
    EVT_HANDLE h{};
    Evt() = default;
    explicit Evt(EVT_HANDLE value) : h(value) {}
    ~Evt() {
        if (h)
            EvtClose(h);
    }
    Evt(const Evt &) = delete;
    Evt &operator=(const Evt &) = delete;
    Evt(Evt &&v) noexcept : h(std::exchange(v.h, nullptr)) {}
    Evt &operator=(Evt &&v) noexcept {
        if (h)
            EvtClose(h);
        h = std::exchange(v.h, nullptr);
        return *this;
    }
};
std::string render(EVT_HANDLE event, DWORD flag) {
    DWORD needed = 0, count = 0;
    EvtRender(nullptr, event, flag, 0, nullptr, &needed, &count);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed > 2 * 1048576)
        throw WindowsError(GetLastError(), "EvtRender sizing");
    std::vector<wchar_t> buffer(needed / sizeof(wchar_t) + 1);
    if (!EvtRender(nullptr, event, flag, needed, buffer.data(), &needed, &count))
        throw WindowsError(GetLastError(), "EvtRender");
    return utf8(buffer.data());
}
} // namespace
struct EventLogMonitor::Impl {
    struct Channel {
        std::string name;
        Handle signal;
        Evt subscription, bookmark;
    };
    EventBus &bus;
    Config config;
    StoreWorker &store;
    Handle stop;
    std::vector<std::unique_ptr<Channel>> channels;
    std::jthread worker;
    Impl(EventBus &b, Config c, StoreWorker &s) : bus(b), config(std::move(c)), store(s) {}
    void gap(const std::string &name, const std::string &reason, DWORD code) {
        monitorStatus(bus, "eventlog/" + name, "degraded", reason, code);
        SecurityEvent e;
        e.type = EventType::CoverageGap;
        e.schemaVersion = 2;
        e.timestampUtc = utcNow();
        e.source = "windows_eventlog";
        e.payload = ObservationPayload{{{"channel", name}, {"reason", reason}, {"windows_error", code}}};
        bus.publish(std::move(e));
    }
    void read(Channel &channel) {
        for (int batch = 0; batch < 128 && !worker.get_stop_token().stop_requested(); ++batch) {
            EVT_HANDLE handles[32]{};
            DWORD count = 0;
            if (!EvtNext(channel.subscription.h, 32, handles, 0, 0, &count)) {
                auto code = GetLastError();
                if (code != ERROR_NO_MORE_ITEMS && code != ERROR_TIMEOUT)
                    gap(channel.name, "Subscription read error; coverage gap", code);
                ResetEvent(channel.signal.value);
                break;
            }
            for (DWORD i = 0; i < count; ++i) {
                Evt event(handles[i]);
                try {
                    auto xml = render(event.h, EvtRenderEventXml);
                    auto record = parseProviderXml(xml);
                    auto events = normalizeProviderRecord(record);
                    if (!EvtUpdateBookmark(channel.bookmark.h, event.h))
                        throw WindowsError(GetLastError(), "EvtUpdateBookmark");
                    auto bookmark = render(channel.bookmark.h, EvtRenderBookmark);
                    for (auto &e : events) {
                        e.bookmarkXml = bookmark;
                        if (config.retain_raw_xml)
                            if (auto p = std::get_if<ObservationPayload>(&e.payload))
                                p->fields["raw_xml"] = xml;
                        if (!bus.publish(std::move(e)))
                            gap(channel.name, "Queue dropped provider event; bookmark not persisted",
                                ERROR_NOT_ENOUGH_MEMORY);
                    }
                } catch (const std::exception &error) {
                    gap(channel.name, error.what(), ERROR_INVALID_DATA);
                }
            }
        }
    }
};
EventLogMonitor::EventLogMonitor(EventBus &b, const Config &c, StoreWorker &s)
    : impl_(std::make_unique<Impl>(b, c, s)) {}
EventLogMonitor::~EventLogMonitor() { stop(); }
void EventLogMonitor::start() {
    auto &p = *impl_;
    p.stop = Handle(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!p.stop.value)
        throw WindowsError(GetLastError(), "Event Log stop event");
    std::set<std::string> names(p.config.eventlog_channels.begin(), p.config.eventlog_channels.end());
    if (p.config.sysmon_auto_detect)
        names.insert("Microsoft-Windows-Sysmon/Operational");
    if (p.config.security_events_enabled)
        names.insert("Security");
    for (auto &name : names) {
        auto channel = std::make_unique<Impl::Channel>();
        channel->name = name;
        channel->signal = Handle(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        auto bookmark = p.store.call({{"op", "get"}, {"table", "log_bookmarks"}, {"key", name}});
        auto xml = bookmark.is_null() ? std::string{} : bookmark.value("xml", std::string{});
        channel->bookmark = Evt(EvtCreateBookmark(xml.empty() ? nullptr : utf16(xml).c_str()));
        if (!channel->bookmark.h) {
            p.gap(name, "Invalid bookmark; explicit restart gap", GetLastError());
            channel->bookmark = Evt(EvtCreateBookmark(nullptr));
            xml.clear();
        }
        auto flags = xml.empty() ? EvtSubscribeToFutureEvents : EvtSubscribeStartAfterBookmark;
        std::wstring query = L"*";
        if (name == "Security")
            query = L"*[System[(EventID=4624 or EventID=4625)]]";
        else if (name == "System")
            query = L"*[System[Provider[@Name='Service Control Manager'] and EventID=7045]]";
        channel->subscription = Evt(EvtSubscribe(nullptr, channel->signal.value, utf16(name).c_str(),
                                                 query.c_str(), xml.empty() ? nullptr : channel->bookmark.h,
                                                 nullptr, nullptr, flags | EvtSubscribeStrict));
        if (!channel->subscription.h) {
            auto error = GetLastError();
            if (!xml.empty() &&
                (error == ERROR_EVT_QUERY_RESULT_STALE || error == ERROR_EVT_QUERY_RESULT_INVALID_POSITION ||
                 error == ERROR_INVALID_DATA)) {
                p.gap(name, "Bookmark no longer retained; subscription resumes future events", error);
                channel->bookmark = Evt(EvtCreateBookmark(nullptr));
                channel->subscription =
                    Evt(EvtSubscribe(nullptr, channel->signal.value, utf16(name).c_str(), query.c_str(),
                                     nullptr, nullptr, nullptr, EvtSubscribeToFutureEvents));
            }
            if (!channel->subscription.h) {
                p.gap(name, "Channel unavailable/denied or subscription failed", GetLastError());
                continue;
            }
        }
        monitorStatus(
            p.bus, "eventlog/" + name, "active",
            "Native subscription; durable event/bookmark transaction; provider policy may omit categories");
        p.channels.push_back(std::move(channel));
    }
    p.worker = std::jthread([&p](std::stop_token stop) {
        std::vector<HANDLE> handles{p.stop.value};
        for (auto &channel : p.channels)
            handles.push_back(channel->signal.value);
        while (!stop.stop_requested()) {
            auto wait =
                WaitForMultipleObjects(static_cast<DWORD>(handles.size()), handles.data(), FALSE, 1000);
            if (wait == WAIT_OBJECT_0)
                break;
            if (wait >= WAIT_OBJECT_0 + 1 && wait < WAIT_OBJECT_0 + handles.size())
                p.read(*p.channels[wait - WAIT_OBJECT_0 - 1]);
            else if (wait == WAIT_FAILED) {
                p.gap("subscriber", "wait failed", GetLastError());
                break;
            }
        }
    });
}
void EventLogMonitor::stop() noexcept {
    if (!impl_)
        return;
    auto &p = *impl_;
    if (p.worker.joinable()) {
        p.worker.request_stop();
        SetEvent(p.stop.value);
        p.worker.join();
    }
    p.channels.clear();
}
std::vector<SecurityEvent> importEventLog(const std::string &path) {
    std::vector<SecurityEvent> events;
    if (lower(filesystemPath(path).extension().string()) == ".xml") {
        std::ifstream file(filesystemPath(path), std::ios::binary);
        file.seekg(0, std::ios::end);
        auto length = file.tellg();
        if (length < 0 || length > 1048576)
            throw std::runtime_error("XML input exceeds 1 MiB");
        file.seekg(0);
        std::string xml(static_cast<std::size_t>(length), '\0');
        file.read(xml.data(), length);
        return normalizeProviderRecord(parseProviderXml(xml));
    }
    Evt query(EvtQuery(nullptr, utf16(path).c_str(), L"*", EvtQueryFilePath | EvtQueryForwardDirection));
    if (!query.h)
        throw WindowsError(GetLastError(), "EvtQuery offline EVTX");
    for (;;) {
        EVT_HANDLE raw[32]{};
        DWORD count = 0;
        if (!EvtNext(query.h, 32, raw, 1000, 0, &count)) {
            auto error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS)
                break;
            throw WindowsError(error, "EvtNext offline EVTX");
        }
        for (DWORD i = 0; i < count; ++i) {
            Evt event(raw[i]);
            auto normalized = normalizeProviderRecord(parseProviderXml(render(event.h, EvtRenderEventXml)));
            events.insert(events.end(), normalized.begin(), normalized.end());
            if (events.size() > 100000)
                throw std::runtime_error("EVTX import event budget exceeded");
        }
    }
    return events;
}
#endif
} // namespace irforge
