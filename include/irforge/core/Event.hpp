#pragma once
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <variant>
#include <vector>
namespace irforge {
using Json = nlohmann::json;
using Millis = std::int64_t;
using ProcessId = std::uint32_t;
using EventId = std::uint64_t;
enum class EventType {
    ProcessStart,
    ProcessExit,
    TcpConnectionObserved,
    TcpConnectionClosed,
    RegistryValueAdded,
    RegistryValueModified,
    RegistryValueDeleted,
    RegistryKeyAdded,
    RegistryKeyDeleted,
    MonitorStatus
};
struct ProcessIdentity {
    ProcessId pid{};
    std::optional<std::uint64_t> creationTime100ns;
    std::uint64_t generation{};
    bool operator==(const ProcessIdentity &) const = default;
};
struct ProcessPayload {
    ProcessIdentity identity;
    std::optional<ProcessId> parentPid;
    std::optional<std::string> imagePath, commandLine;
    std::optional<std::uint32_t> exitCode;
    bool initialEnumeration = false;
};
struct TcpPayload {
    ProcessId ownerPid{};
    std::optional<std::uint64_t> ownerCreationTime100ns;
    std::string protocol, localAddress, remoteAddress, state;
    std::uint16_t localPort{}, remotePort{};
    bool firstSnapshot = false;
    std::string change = "appeared";
    bool operator==(const TcpPayload &) const = default;
};
struct RegistryValue {
    std::uint32_t type{};
    std::vector<std::uint8_t> raw;
    std::optional<std::string> text;
    std::optional<std::uint32_t> dword;
    bool operator==(const RegistryValue &) const = default;
};
struct RegistryPayload {
    std::string hive, keyPath, valueName, view;
    std::optional<RegistryValue> oldData, newData;
    std::optional<ProcessId> actorPid;
    std::optional<std::string> serviceImage;
    std::optional<std::uint32_t> serviceStart, serviceType;
};
struct StatusPayload {
    std::string state, message;
    std::uint32_t errorCode{};
    std::uint64_t eventsLost{}, buffersLost{}, decodeErrors{};
};
using EventPayload = std::variant<ProcessPayload, TcpPayload, RegistryPayload, StatusPayload>;
struct SecurityEvent {
    EventId id{};
    EventType type{};
    Millis timestampUtc{};
    std::chrono::steady_clock::time_point receivedAt = std::chrono::steady_clock::now();
    std::string source, host;
    EventPayload payload = ProcessPayload{};
};
std::string eventTypeName(EventType);
EventType parseEventType(const std::string &);
std::string formatUtc(Millis);
Millis parseUtc(const std::string &);
Millis utcNow();
std::string utf8(const std::wstring &);
std::wstring utf16(const std::string &);
std::string lower(std::string);
std::string normalizePath(std::string);
std::optional<std::string> executablePath(const std::string &);
std::string baseName(const std::string &);
std::string identityKey(const ProcessIdentity &);
std::string addressClass(const std::string &);
std::filesystem::path filesystemPath(const std::string &);
bool userWritablePath(const std::string &);
void to_json(Json &, const SecurityEvent &);
void from_json(const Json &, SecurityEvent &);
Json identityJson(const ProcessIdentity &);
Json readJsonFile(const std::string &, std::size_t maxBytes = 1024 * 1024);
} // namespace irforge
