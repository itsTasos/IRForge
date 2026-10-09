#include "irforge/core/Event.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <codecvt>
#include <locale>
#endif
namespace irforge {
namespace {
const std::vector<std::string> names = {"process_start",
                                        "process_exit",
                                        "tcp_connection_observed",
                                        "tcp_connection_closed",
                                        "registry_value_added",
                                        "registry_value_modified",
                                        "registry_value_deleted",
                                        "registry_key_added",
                                        "registry_key_deleted",
                                        "monitor_status",
                                        "file_created",
                                        "file_modified",
                                        "file_deleted",
                                        "file_renamed",
                                        "artifact_enriched",
                                        "scheduled_task_added",
                                        "scheduled_task_changed",
                                        "scheduled_task_removed",
                                        "service_created",
                                        "service_changed",
                                        "service_removed",
                                        "startup_entry_added",
                                        "startup_entry_changed",
                                        "startup_entry_removed",
                                        "logon_observed",
                                        "dns_observed",
                                        "sysmon_network_connect",
                                        "sysmon_registry_change",
                                        "hash_completed",
                                        "signature_checked",
                                        "yara_match",
                                        "baseline_deviation",
                                        "threat_intel_result",
                                        "coverage_gap",
                                        "dropped_events",
                                        "watcher_restart",
                                        "health_changed",
                                        "unmapped"};
template <class T> Json opt(const std::optional<T> &x) { return x ? Json(*x) : Json(nullptr); }
template <class T> std::optional<T> optional(const Json &j, const char *key) {
    if (!j.contains(key) || j.at(key).is_null())
        return {};
    return j.at(key).get<T>();
}
Json val(const std::optional<RegistryValue> &v) {
    if (!v)
        return nullptr;
    return {{"type", v->type}, {"raw", v->raw}, {"text", opt(v->text)}, {"dword", opt(v->dword)}};
}
std::optional<RegistryValue> reg(const Json &j) {
    if (j.is_null())
        return {};
    RegistryValue v;
    if (!j.at("type").is_number_integer() || j.at("type") < 0 || j.at("type") > UINT32_MAX)
        throw std::runtime_error("invalid Registry value type");
    if (!j.at("raw").is_array() || j.at("raw").size() > 65536)
        throw std::runtime_error("invalid Registry raw data");
    for (const auto &byte : j.at("raw"))
        if (!byte.is_number_integer() || byte < 0 || byte > 255)
            throw std::runtime_error("invalid Registry byte");
    v.type = j.at("type").get<std::uint32_t>();
    v.raw = j.at("raw").get<std::vector<std::uint8_t>>();
    if (v.raw.size() > 65536)
        throw std::runtime_error("Registry value exceeds 64 KiB");
    v.text = optional<std::string>(j, "text");
    v.dword = optional<std::uint32_t>(j, "dword");
    return v;
}
} // namespace
std::string eventTypeName(EventType t) { return names.at(static_cast<std::size_t>(t)); }
EventType parseEventType(const std::string &s) {
    auto i = std::find(names.begin(), names.end(), s);
    if (i == names.end())
        throw std::runtime_error("unknown event_type: " + s);
    return static_cast<EventType>(i - names.begin());
}
Millis utcNow() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
std::string formatUtc(Millis t) {
    auto seconds = static_cast<std::time_t>(t / 1000);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &seconds);
#else
    gmtime_r(&seconds, &tm);
#endif
    std::ostringstream o;
    o << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << '.' << std::setw(3) << std::setfill('0') << (t % 1000)
      << 'Z';
    return o.str();
}
Millis parseUtc(const std::string &s) {
    if (s.size() != 24 || s[19] != '.' || s[23] != 'Z' || !std::isdigit(static_cast<unsigned char>(s[20])) ||
        !std::isdigit(static_cast<unsigned char>(s[21])) || !std::isdigit(static_cast<unsigned char>(s[22])))
        throw std::runtime_error("timestamp must be RFC3339 UTC with millisecond precision");
    std::tm tm{};
    std::istringstream in(s.substr(0, 19));
    in >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    if (in.fail())
        throw std::runtime_error("invalid timestamp: " + s);
#ifdef _WIN32
    auto t = _mkgmtime(&tm);
#else
    auto t = timegm(&tm);
#endif
    Millis result = static_cast<Millis>(t) * 1000 + std::stoi(s.substr(20, 3));
    if (t < 0 || formatUtc(result) != s)
        throw std::runtime_error("invalid timestamp: " + s);
    return result;
}
std::string utf8(const std::wstring &w) {
    if (w.empty())
        return {};
#ifdef _WIN32
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.data(), static_cast<int>(w.size()), nullptr,
                                0, nullptr, nullptr);
    if (!n)
        throw std::runtime_error("invalid UTF-16");
    std::string s(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.data(), static_cast<int>(w.size()), s.data(), n,
                        nullptr, nullptr);
    return s;
#else
    return std::wstring_convert<std::codecvt_utf8<wchar_t>>{}.to_bytes(w);
#endif
}
std::wstring utf16(const std::string &s) {
    if (s.empty())
        return {};
#ifdef _WIN32
    int n =
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (!n)
        throw std::runtime_error("invalid UTF-8");
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
#else
    return std::wstring_convert<std::codecvt_utf8<wchar_t>>{}.from_bytes(s);
#endif
}
std::string lower(std::string s) {
#ifdef _WIN32
    auto w = utf16(s);
    if (w.empty())
        return s;
    int n = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, w.data(), static_cast<int>(w.size()),
                          nullptr, 0, nullptr, nullptr, 0);
    if (n > 0) {
        std::wstring out(static_cast<std::size_t>(n), L'\0');
        LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, w.data(), static_cast<int>(w.size()),
                      out.data(), n, nullptr, nullptr, 0);
        return utf8(out);
    }
#endif
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}
std::string normalizePath(std::string s) {
    s = lower(std::move(s));
    std::replace(s.begin(), s.end(), '/', '\\');
    if (s.starts_with("\\??\\") || s.starts_with("\\\\?\\"))
        s.erase(0, 4);
    std::vector<std::string> parts;
    std::istringstream in(s);
    std::string p;
    while (std::getline(in, p, '\\')) {
        if (p == ".")
            continue;
        if (p == "..") {
            if (parts.size() > 1)
                parts.pop_back();
            else
                return {};
        } else
            parts.push_back(p);
    }
    std::string out;
    for (const auto &v : parts) {
        if (!out.empty())
            out += '\\';
        out += v;
    }
    return out;
}
std::optional<std::string> executablePath(const std::string &command) {
    auto start = command.find_first_not_of(" \t");
    if (start == std::string::npos)
        return {};
    std::string path;
    if (command[start] == '"') {
        auto end = command.find('"', start + 1);
        if (end == std::string::npos)
            return {};
        path = command.substr(start + 1, end - start - 1);
    } else {
        auto end = command.find_first_of(" \t", start);
        path = command.substr(start, end == std::string::npos ? end : end - start);
    }
    path = normalizePath(path);
    // Do not guess expansion, unquoted paths with spaces, relative commands or shell indirection.
    if (path.size() < 4 || path[1] != ':' || path[2] != '\\' || !path.ends_with(".exe"))
        return {};
    return path;
}
std::string baseName(const std::string &p) {
    auto i = p.find_last_of("/\\");
    return lower(i == std::string::npos ? p : p.substr(i + 1));
}
bool userWritablePath(const std::string &s) {
    auto p = executablePath(s);
    if (!p)
        return false;
    return p->find("\\users\\") != std::string::npos || p->find("\\windows\\temp\\") != std::string::npos ||
           p->find("\\temp\\") != std::string::npos;
}
std::string identityKey(const ProcessIdentity &i) {
    if (i.processGuid)
        return "guid/" + lower(*i.processGuid);
    return std::to_string(i.pid) + ":" +
           (i.creationTime100ns ? "c" + std::to_string(*i.creationTime100ns)
                                : "g" + std::to_string(i.generation));
}
std::string addressClass(const std::string &input) {
    auto s = input.substr(0, input.find('%'));
    std::array<unsigned char, 16> b{};
    if (inet_pton(AF_INET, s.c_str(), b.data()) == 1) {
        if (b[0] == 0)
            return "unspecified";
        if (b[0] == 127)
            return "loopback";
        if (b[0] == 169 && b[1] == 254)
            return "link_local";
        if (b[0] >= 224 && b[0] <= 239)
            return "multicast";
        if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) ||
            (b[0] == 100 && b[1] >= 64 && b[1] <= 127))
            return "private_local";
        if (b[0] >= 240 || (b[0] == 192 && b[1] == 0) || (b[0] == 192 && b[1] == 2) ||
            (b[0] == 198 && (b[1] == 18 || b[1] == 19 || b[1] == 51)) ||
            (b[0] == 203 && b[1] == 0 && b[2] == 113))
            return "reserved";
        return "public";
    }
    if (inet_pton(AF_INET6, s.c_str(), b.data()) != 1)
        return "invalid";
    bool zero = std::all_of(b.begin(), b.end(), [](auto v) { return v == 0; });
    if (zero)
        return "unspecified";
    if (std::all_of(b.begin(), b.end() - 1, [](auto v) { return v == 0; }) && b[15] == 1)
        return "loopback";
    if (std::all_of(b.begin(), b.begin() + 10, [](auto v) { return v == 0; }) && b[10] == 255 && b[11] == 255)
        return addressClass(std::to_string(b[12]) + "." + std::to_string(b[13]) + "." +
                            std::to_string(b[14]) + "." + std::to_string(b[15]));
    if (b[0] == 255)
        return "multicast";
    if (b[0] == 254 && (b[1] & 192) == 128)
        return "link_local";
    if ((b[0] & 254) == 252)
        return "private_local";
    if (b[0] == 0x20 && b[1] == 1 && b[2] == 0x0d && b[3] == 0xb8)
        return "reserved";
    return (b[0] & 224) == 32 ? "public" : "reserved";
}
Json identityJson(const ProcessIdentity &i) {
    Json result = {
        {"pid", i.pid}, {"creation_time_100ns", opt(i.creationTime100ns)}, {"generation", i.generation}};
    if (i.processGuid)
        result["sysmon_process_guid"] = *i.processGuid;
    return result;
}
void to_json(Json &j, const SecurityEvent &e) {
    j = {{"schema_version", 1},
         {"event_id", e.id},
         {"event_type", eventTypeName(e.type)},
         {"timestamp_utc", formatUtc(e.timestampUtc)},
         {"source", e.source},
         {"host", e.host}};
    Json p;
    if (auto x = std::get_if<ProcessPayload>(&e.payload))
        p = {{"identity", identityJson(x->identity)}, {"parent_pid", opt(x->parentPid)},
             {"image_path", opt(x->imagePath)},       {"command_line", opt(x->commandLine)},
             {"exit_code", opt(x->exitCode)},         {"initial_enumeration", x->initialEnumeration}};
    else if (auto x = std::get_if<TcpPayload>(&e.payload))
        p = {{"owner_pid", x->ownerPid},
             {"owner_creation_time_100ns", opt(x->ownerCreationTime100ns)},
             {"protocol", x->protocol},
             {"local_address", x->localAddress},
             {"local_port", x->localPort},
             {"remote_address", x->remoteAddress},
             {"remote_port", x->remotePort},
             {"state", x->state},
             {"first_snapshot", x->firstSnapshot},
             {"change", x->change}};
    else if (auto x = std::get_if<RegistryPayload>(&e.payload))
        p = {{"hive", x->hive},
             {"key_path", x->keyPath},
             {"value_name", x->valueName},
             {"view", x->view},
             {"old_data", val(x->oldData)},
             {"new_data", val(x->newData)},
             {"actor_pid", opt(x->actorPid)},
             {"service_image", opt(x->serviceImage)},
             {"service_start", opt(x->serviceStart)},
             {"service_type", opt(x->serviceType)}};
    else if (auto x = std::get_if<FilePayload>(&e.payload))
        p = {{"path", x->path},
             {"previous_path", x->previousPath},
             {"action", x->action},
             {"actor_pid", opt(x->actorPid)},
             {"metadata", x->metadata}};
    else if (auto x = std::get_if<InventoryPayload>(&e.payload))
        p = {{"kind", x->kind},     {"key", x->key},     {"action", x->action},
             {"before", x->before}, {"after", x->after}, {"initial_snapshot", x->initialSnapshot}};
    else if (auto x = std::get_if<ObservationPayload>(&e.payload))
        p = x->fields;
    else {
        auto &st = std::get<StatusPayload>(e.payload);
        p = {{"state", st.state},
             {"message", st.message},
             {"error_code", st.errorCode},
             {"events_lost", st.eventsLost},
             {"buffers_lost", st.buffersLost},
             {"decode_errors", st.decodeErrors}};
    }
    j["payload"] = std::move(p);
    if (auto x = std::get_if<ProcessPayload>(&e.payload); x && x->parentProcessGuid)
        j["payload"]["parent_process_guid"] = *x->parentProcessGuid;
    if (auto x = std::get_if<ProcessPayload>(&e.payload); x && x->parentImagePath)
        j["payload"]["parent_image_path"] = *x->parentImagePath;
    if (auto x = std::get_if<TcpPayload>(&e.payload); x && x->ownerProcessGuid)
        j["payload"]["owner_process_guid"] = *x->ownerProcessGuid;
    if (e.schemaVersion == 2 || static_cast<int>(e.type) > static_cast<int>(EventType::MonitorStatus)) {
        j["schema_version"] = 2;
        j["sequence"] = e.id;
        j["event_id"] =
            e.uniqueId.empty() ? e.hostId + "/" + e.sessionId + "/" + std::to_string(e.id) : e.uniqueId;
        j["host_id"] = e.hostId;
        j["session_id"] = e.sessionId;
        j["observed_at_utc"] = formatUtc(e.observedAtUtc ? e.observedAtUtc : e.timestampUtc);
        j["source_record_id"] = e.sourceRecordId.empty() ? Json(nullptr) : Json(e.sourceRecordId);
        j["attribution"] = {{"method", e.attributionMethod}, {"confidence", e.attributionConfidence}};
        j["data_quality"] = {{"partial", e.partial}, {"missing_data", e.missingData}};
        j["privacy"] = {{"redacted", e.redacted}};
        if (!e.providerChannel.empty())
            j["provider_channel"] = e.providerChannel;
        if (!e.bookmarkXml.empty())
            j["bookmark_xml"] = e.bookmarkXml;
    }
}
void from_json(const Json &input, SecurityEvent &e) {
    Json j = input;
    if (!j.is_object() || !j.contains("schema_version") ||
        (j.at("schema_version") != 1 && j.at("schema_version") != 2))
        throw std::runtime_error("unsupported event schema");
    if (j["schema_version"] == 2) {
        e.schemaVersion = 2;
        e.uniqueId = j.at("event_id").get<std::string>();
        e.hostId = j.at("host_id").get<std::string>();
        e.sessionId = j.at("session_id").get<std::string>();
        if (e.uniqueId.empty() || e.uniqueId.size() > 512 || e.hostId.empty() || e.sessionId.empty())
            throw std::runtime_error("v2 requires bounded stable event/host/session identities");
        j["event_id"] = j.at("sequence");
        if (!j.contains("event_type") && j.contains("type"))
            j["event_type"] = j["type"];
        e.observedAtUtc = parseUtc(j.at("observed_at_utc").get<std::string>());
        e.sourceRecordId = optional<std::string>(j, "source_record_id").value_or("");
        auto a = j.value("attribution", Json::object());
        e.attributionMethod = a.value("method", std::string("unknown"));
        e.attributionConfidence = a.value("confidence", std::string("low"));
        if (e.attributionConfidence != "low" && e.attributionConfidence != "medium" &&
            e.attributionConfidence != "high")
            throw std::runtime_error("invalid attribution confidence");
        e.partial = j.value("data_quality", Json::object()).value("partial", false);
        e.missingData =
            j.value("data_quality", Json::object()).value("missing_data", std::vector<std::string>{});
        e.redacted = j.value("privacy", Json::object()).value("redacted", false);
        e.providerChannel = j.value("provider_channel", std::string{});
        e.bookmarkXml = j.value("bookmark_xml", std::string{});
        if (e.providerChannel.size() > 512 || e.bookmarkXml.size() > 16384)
            throw std::runtime_error("invalid provider cursor size");
    }
    auto integer = [](const Json &object, const char *key, std::uint64_t max, bool nullable = false) {
        if (nullable && (!object.contains(key) || object.at(key).is_null()))
            return;
        const auto &value = object.at(key);
        if (!value.is_number_integer() || (!value.is_number_unsigned() && value.get<std::int64_t>() < 0) ||
            value.get<std::uint64_t>() > max)
            throw std::runtime_error(std::string("invalid integer field: ") + key);
    };
    integer(j, "event_id", UINT64_MAX);
    e.id = j.at("event_id").get<EventId>();
    e.type = parseEventType(j.at("event_type").get<std::string>());
    e.timestampUtc = parseUtc(j.at("timestamp_utc").get<std::string>());
    e.source = j.at("source").get<std::string>();
    e.host = j.at("host").get<std::string>();
    const auto &p = j.at("payload");
    if (e.type == EventType::ProcessStart || e.type == EventType::ProcessExit) {
        ProcessPayload x;
        const auto &i = p.at("identity");
        integer(i, "pid", UINT32_MAX);
        integer(i, "creation_time_100ns", UINT64_MAX, true);
        integer(i, "generation", UINT64_MAX, true);
        integer(p, "parent_pid", UINT32_MAX, true);
        integer(p, "exit_code", UINT32_MAX, true);
        x.identity = {i.at("pid").get<ProcessId>(),
                      optional<std::uint64_t>(i, "creation_time_100ns"),
                      i.value("generation", std::uint64_t{}),
                      {}};
        x.parentPid = optional<ProcessId>(p, "parent_pid");
        x.imagePath = optional<std::string>(p, "image_path");
        x.commandLine = optional<std::string>(p, "command_line");
        x.exitCode = optional<std::uint32_t>(p, "exit_code");
        x.initialEnumeration = p.value("initial_enumeration", false);
        x.identity.processGuid = optional<std::string>(i, "sysmon_process_guid");
        x.parentProcessGuid = optional<std::string>(p, "parent_process_guid");
        x.parentImagePath = optional<std::string>(p, "parent_image_path");
        e.payload = x;
    } else if (e.type == EventType::TcpConnectionObserved || e.type == EventType::TcpConnectionClosed ||
               e.type == EventType::SysmonNetworkConnect) {
        TcpPayload x;
        integer(p, "owner_pid", UINT32_MAX);
        integer(p, "owner_creation_time_100ns", UINT64_MAX, true);
        integer(p, "local_port", 65535);
        integer(p, "remote_port", 65535);
        x.ownerPid = p.at("owner_pid").get<ProcessId>();
        x.ownerCreationTime100ns = optional<std::uint64_t>(p, "owner_creation_time_100ns");
        x.protocol = p.at("protocol").get<std::string>();
        x.localAddress = p.at("local_address").get<std::string>();
        x.remoteAddress = p.at("remote_address").get<std::string>();
        auto lp = p.at("local_port").get<int>(), rp = p.at("remote_port").get<int>();
        if (lp < 0 || lp > 65535 || rp < 0 || rp > 65535 || addressClass(x.localAddress) == "invalid" ||
            addressClass(x.remoteAddress) == "invalid" || (x.protocol != "tcp4" && x.protocol != "tcp6"))
            throw std::runtime_error("malformed TCP endpoint");
        x.localPort = static_cast<std::uint16_t>(lp);
        x.remotePort = static_cast<std::uint16_t>(rp);
        x.state = p.at("state").get<std::string>();
        x.firstSnapshot = p.value("first_snapshot", false);
        x.change = p.value("change", std::string("appeared"));
        x.ownerProcessGuid = optional<std::string>(p, "owner_process_guid");
        e.payload = x;
    } else if (e.type == EventType::MonitorStatus) {
        e.payload = StatusPayload{p.at("state").get<std::string>(),
                                  p.at("message").get<std::string>(),
                                  p.value("error_code", 0u),
                                  p.value("events_lost", std::uint64_t{}),
                                  p.value("buffers_lost", std::uint64_t{}),
                                  p.value("decode_errors", std::uint64_t{})};
    } else if ((e.type >= EventType::RegistryValueAdded && e.type <= EventType::RegistryKeyDeleted) ||
               e.type == EventType::SysmonRegistryChange) {
        RegistryPayload x;
        integer(p, "actor_pid", UINT32_MAX, true);
        integer(p, "service_start", UINT32_MAX, true);
        integer(p, "service_type", UINT32_MAX, true);
        x.hive = p.at("hive").get<std::string>();
        x.keyPath = p.at("key_path").get<std::string>();
        x.valueName = p.value("value_name", std::string{});
        x.view = p.value("view", std::string("64"));
        x.oldData = reg(p.value("old_data", Json(nullptr)));
        x.newData = reg(p.value("new_data", Json(nullptr)));
        x.actorPid = optional<ProcessId>(p, "actor_pid");
        x.serviceImage = optional<std::string>(p, "service_image");
        x.serviceStart = optional<std::uint32_t>(p, "service_start");
        x.serviceType = optional<std::uint32_t>(p, "service_type");
        e.payload = x;
    } else if (e.type >= EventType::FileCreated && e.type <= EventType::ArtifactEnriched) {
        e.payload = FilePayload{p.at("path").get<std::string>(), p.value("previous_path", std::string{}),
                                p.value("action", std::string{}), optional<ProcessId>(p, "actor_pid"),
                                p.value("metadata", Json::object())};
    } else if (e.type >= EventType::ScheduledTaskAdded && e.type <= EventType::StartupEntryRemoved) {
        e.payload = InventoryPayload{p.at("kind").get<std::string>(),   p.at("key").get<std::string>(),
                                     p.at("action").get<std::string>(), p.value("before", Json(nullptr)),
                                     p.value("after", Json(nullptr)),   p.value("initial_snapshot", false)};
    } else {
        if (!p.is_object())
            throw std::runtime_error("observation payload must be an object");
        e.payload = ObservationPayload{p};
    }
    // A whole line is bounded by replay; also reject huge individual strings from any caller.
    if (j.dump().size() > 1048576)
        throw std::runtime_error("event exceeds 1 MiB");
}
std::filesystem::path filesystemPath(const std::string &s) {
    return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t *>(s.data()), s.size()));
}
Json readJsonFile(const std::string &path, std::size_t maxBytes) {
    std::ifstream f(filesystemPath(path), std::ios::binary);
    if (!f)
        throw std::runtime_error("cannot open " + path);
    f.seekg(0, std::ios::end);
    auto n = f.tellg();
    if (n < 0 || n > static_cast<std::streamoff>(maxBytes))
        throw std::runtime_error(path + ": file too large");
    f.seekg(0);
    try {
        return Json::parse(f, [](int depth, Json::parse_event_t, Json &) {
            if (depth > 32)
                throw std::runtime_error("JSON nesting exceeds 32 levels");
            return true;
        });
    } catch (const std::exception &ex) {
        throw std::runtime_error(path + ": " + ex.what());
    }
}
} // namespace irforge
