#include "irforge/monitoring/Diff.hpp"
#include <cstring>
#include <stdexcept>
namespace irforge {
namespace {
std::string endpointKey(const TcpPayload &p) {
    return p.protocol + "/" + p.localAddress + ":" + std::to_string(p.localPort) + "/" + p.remoteAddress +
           ":" + std::to_string(p.remotePort) + "/" + std::to_string(p.ownerPid) + "/" +
           (p.ownerCreationTime100ns ? std::to_string(*p.ownerCreationTime100ns) : "unknown");
}
SecurityEvent networkEvent(EventType type, TcpPayload p, Millis t) {
    SecurityEvent e;
    e.type = type;
    e.timestampUtc = t;
    e.source = "network";
    e.payload = std::move(p);
    return e;
}
} // namespace
std::vector<SecurityEvent> NetworkDiff::update(const std::vector<TcpPayload> &rows, Millis t, bool success) {
    if (!success)
        return {}; // A failed query must never erase the last successful table.
    std::map<std::string, TcpPayload> current;
    for (const auto &p : rows)
        current[endpointKey(p)] = p;
    std::vector<SecurityEvent> out;
    for (const auto &[key, row] : current) {
        auto old = previous_.find(key);
        auto p = row;
        p.firstSnapshot = !initialized_;
        if (old == previous_.end())
            out.push_back(networkEvent(EventType::TcpConnectionObserved, p, t));
        else if (old->second.state != p.state) {
            p.change = "state_changed";
            out.push_back(networkEvent(EventType::TcpConnectionObserved, p, t));
        }
    }
    for (const auto &[key, row] : previous_)
        if (!current.contains(key)) {
            auto p = row;
            p.firstSnapshot = false;
            p.change = "disappeared";
            out.push_back(networkEvent(EventType::TcpConnectionClosed, p, t));
        }
    previous_ = std::move(current);
    initialized_ = true;
    return out;
}
RegistryValue decodeRegistryValue(std::uint32_t type, const std::vector<std::uint8_t> &data) {
    if (data.size() > 65536)
        throw std::runtime_error("Registry value exceeds 64 KiB");
    RegistryValue v{type, data, {}, {}};
    if (type == 1 || type == 2) {
        if (data.size() % 2 != 0)
            throw std::runtime_error("odd UTF-16 registry value length");
        std::wstring text;
        for (std::size_t n = 0; n + 1 < data.size(); n += 2) {
            auto c = static_cast<wchar_t>(data[n] | (static_cast<unsigned>(data[n + 1]) << 8));
            if (c == 0)
                break;
            text.push_back(c);
        }
        v.text = utf8(text);
    } else if (type == 4) {
        if (data.size() != 4)
            throw std::runtime_error("invalid REG_DWORD length");
        v.dword = static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8) |
                  (static_cast<std::uint32_t>(data[2]) << 16) | (static_cast<std::uint32_t>(data[3]) << 24);
    }
    return v;
}
std::vector<SecurityEvent> registryDiff(const RegistrySnapshot &before, const RegistrySnapshot &after,
                                        const std::string &hive, const std::string &view, Millis t) {
    std::vector<SecurityEvent> out;
    auto emit = [&](EventType type, const std::string &path, const std::string &name,
                    std::optional<RegistryValue> old, std::optional<RegistryValue> value) {
        RegistryPayload p;
        p.hive = hive;
        p.keyPath = path;
        p.valueName = name;
        p.view = view;
        p.oldData = std::move(old);
        p.newData = std::move(value);
        p.actorPid = std::nullopt;
        auto key = after.keys.find(path);
        if (key != after.keys.end()) {
            for (const auto &[n, v] : key->second) {
                auto low = lower(n);
                if (low == "imagepath")
                    p.serviceImage = v.text;
                if (low == "start")
                    p.serviceStart = v.dword;
                if (low == "type")
                    p.serviceType = v.dword;
            }
        }
        SecurityEvent e;
        e.type = type;
        e.timestampUtc = t;
        e.source = "registry";
        e.payload = std::move(p);
        out.push_back(std::move(e));
    };
    for (const auto &[path, values] : after.keys) {
        auto previous = before.keys.find(path);
        if (previous == before.keys.end())
            emit(EventType::RegistryKeyAdded, path, "", {}, {});
        for (const auto &[name, value] : values) {
            if (previous == before.keys.end() || !previous->second.contains(name))
                emit(EventType::RegistryValueAdded, path, name, {}, value);
            else if (previous->second.at(name) != value)
                emit(EventType::RegistryValueModified, path, name, previous->second.at(name), value);
        }
        if (previous != before.keys.end())
            for (const auto &[name, value] : previous->second)
                if (!values.contains(name))
                    emit(EventType::RegistryValueDeleted, path, name, value, {});
    }
    for (const auto &[path, values] : before.keys)
        if (!after.keys.contains(path)) {
            for (const auto &[name, value] : values)
                emit(EventType::RegistryValueDeleted, path, name, value, {});
            emit(EventType::RegistryKeyDeleted, path, "", {}, {});
        }
    return out;
}
} // namespace irforge
