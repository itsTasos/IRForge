#include "irforge/remote/RemoteProtocol.hpp"
#include "irforge/ti/VirusTotal.hpp"
#include <set>
namespace irforge {
namespace {
bool identifier(const std::string &value) {
    return !value.empty() && value.size() <= 128 &&
           value.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_{}") ==
               std::string::npos;
}
} // namespace
void validateEnrollment(const Json &j) {
    validateDocument(j);
    if (j.at("schema_version") != 1 || !VirusTotalClient::validHash(j.at("fingerprint").get<std::string>()) ||
        !identifier(j.at("agent_id").get<std::string>()) || !identifier(j.at("host_id").get<std::string>()) ||
        !std::set<std::string>{"agent", "viewer", "admin"}.contains(j.at("role").get<std::string>()) ||
        !j.at("revoked").is_boolean())
        throw std::runtime_error("invalid certificate enrollment");
    if (j.contains("allowed_hosts")) {
        auto hosts = j["allowed_hosts"].get<std::vector<std::string>>();
        if (hosts.size() > 128)
            throw std::runtime_error("enrollment host scope bound");
        for (const auto &host : hosts)
            if (!(identifier(host) || (host == "*" && j["role"] == "admin")))
                throw std::runtime_error("invalid enrollment host scope");
    }
}
Json redactRemoteEvent(Json j, bool commands) {
    validateDocument(j);
    auto e = j.get<SecurityEvent>();
    if (e.schemaVersion != 2)
        throw std::runtime_error("remote transport requires schema v2");
    auto &payload = j["payload"];
    bool changed = false;
    if (commands && payload.contains("command_line") && !payload["command_line"].is_null()) {
        payload["command_line"] = nullptr;
        changed = true;
        j["data_quality"]["missing_data"].push_back("remote_command_line_redacted");
    }
    for (const auto *field : {"old_data", "new_data"})
        if (payload.contains(field) && payload[field].is_object()) {
            if (payload[field].contains("raw")) {
                payload[field]["raw"] = Json::array();
                changed = true;
            }
            if (commands && payload[field].contains("text")) {
                payload[field]["text"] = nullptr;
                changed = true;
            }
        }
    if (payload.contains("fields") && payload["fields"].is_object()) {
        auto &fields = payload["fields"];
        if (fields.contains("raw_xml")) {
            fields.erase("raw_xml");
            changed = true;
        }
        if (e.type == EventType::Unmapped && fields.contains("fields")) {
            fields["fields"] = Json::object();
            j["data_quality"]["missing_data"].push_back("unmapped_provider_fields_omitted_for_remote");
            changed = true;
        }
    }
    if (!j.value("bookmark_xml", std::string{}).empty())
        j.erase("bookmark_xml");
    j.erase("provider_channel");
    if (changed) {
        j["privacy"]["redacted"] = true;
        j["data_quality"]["partial"] = true;
    }
    return j;
}
Json validateRemotePacket(const Json &packet, const Json &enrollment) {
    validateEnrollment(enrollment);
    validateDocument(packet);
    if (enrollment["revoked"] == true || enrollment["role"] != "agent")
        throw std::runtime_error("certificate is revoked or lacks agent ingest role");
    if (packet.at("schema_version") != 1 || packet.at("agent_id") != enrollment.at("agent_id") ||
        packet.at("host_id") != enrollment.at("host_id") ||
        (!packet.at("sequence").is_number_unsigned() &&
         (!packet.at("sequence").is_number_integer() || packet.at("sequence").get<std::int64_t>() < 1)))
        throw std::runtime_error("remote identity/version/sequence mismatch");
    auto sequence = packet.at("sequence").get<std::uint64_t>();
    if (sequence < 1 || sequence > static_cast<std::uint64_t>(INT64_MAX))
        throw std::runtime_error("remote sequence outside durable range");
    const auto kind = packet.at("kind").get<std::string>();
    const auto session = packet.at("session_id").get<std::string>();
    if (!identifier(session))
        throw std::runtime_error("invalid remote session identifier");
    if (kind == "event") {
        auto e = packet.at("data").get<SecurityEvent>();
        if (e.schemaVersion != 2 || e.hostId != enrollment.at("host_id").get<std::string>() ||
            e.sessionId != session ||
            e.uniqueId != e.hostId + "/" + e.sessionId + "/" + std::to_string(e.id) || e.id == 0)
            throw std::runtime_error("event host/session not bound to client certificate");
        if (e.bookmarkXml.size() > 0)
            throw std::runtime_error("remote events may not set collector bookmarks");
    } else if (kind == "incident") {
        auto j = packet.at("data");
        if (j.at("schema_version") != 2 || j.at("host_id") != enrollment.at("host_id") ||
            j.at("session_id") != packet.at("session_id") || j.at("risk_score").get<int>() < 0 ||
            j.at("risk_score").get<int>() > 100)
            throw std::runtime_error("incident host/session/score mismatch");
    } else
        throw std::runtime_error(
            "only normalized event and incident metadata is accepted; no files or commands");
    return packet;
}
Json acceptRemoteBatch(StoreWorker &store, const Json &batch, const Json &enrollment) {
    validateDocument(batch);
    if (batch.at("schema_version") != 1 || !batch.at("packets").is_array() || batch.at("packets").empty() ||
        batch["packets"].size() > 100)
        throw std::runtime_error("batch needs 1..100 metadata packets");
    std::string session = batch["packets"][0].at("session_id").get<std::string>();
    if (session.empty() || session.size() > 128)
        throw std::runtime_error("remote session bound");
    std::uint64_t previous = 0;
    for (const auto &packet : batch["packets"]) {
        validateRemotePacket(packet, enrollment);
        auto sequence = packet["sequence"].get<std::uint64_t>();
        if (packet["session_id"] != session || sequence <= previous)
            throw std::runtime_error("batch must have one session and strictly increasing sequences");
        previous = sequence;
    }
    auto key = "remote/receipt/" + enrollment.at("agent_id").get<std::string>() + "/" + session;
    auto receipt = store.call({{"op", "get"}, {"table", "settings"}, {"key", key}});
    std::uint64_t ack = receipt.is_null() ? 0 : receipt.at("ack_sequence").get<std::uint64_t>();
    std::size_t accepted = 0, duplicates = 0;
    Json gaps = Json::array();
    std::string host = enrollment.at("host_id").get<std::string>();
    store.call(
        {{"op", "session"},
         {"host", host},
         {"id", session},
         {"data",
          {{"host", host},
           {"mode", "remote_metadata"},
           {"start_utc", formatUtc(utcNow())},
           {"certificate_fingerprint", enrollment["fingerprint"]},
           {"agent_id", enrollment["agent_id"]},
           {"provenance", "verified mTLS enrollment; remote source observations remain source-reported"}}}});
    for (const auto &packet : batch["packets"]) {
        auto sequence = packet["sequence"].get<std::uint64_t>();
        if (sequence <= ack) {
            ++duplicates;
            continue;
        }
        if (sequence != ack + 1)
            gaps.push_back({{"missing_from", ack + 1},
                            {"missing_to", sequence - 1},
                            {"reason", "transport sequence gap; spool may have expired or overflowed"}});
        if (packet["kind"] == "event") {
            auto event = packet["data"];
            event["remote_provenance"] = {{"certificate_fingerprint", enrollment["fingerprint"]},
                                          {"agent_id", enrollment["agent_id"]},
                                          {"received_at", formatUtc(utcNow())},
                                          {"sequence", sequence}};
            store.call({{"op", "event"}, {"data", event}});
        } else {
            auto incident = packet["data"];
            if (incident.contains("local_incident_id"))
                incident["incident_id"] = incident["local_incident_id"];
            incident["provenance"]["remote_certificate"] = enrollment["fingerprint"];
            incident["provenance"]["analysis"] = "source agent; transported over verified mTLS";
            store.call({{"op", "incident"}, {"data", incident}});
        }
        ack = sequence;
        ++accepted;
    }
    Json result = {{"schema_version", 1},   {"agent_id", enrollment["agent_id"]},
                   {"session_id", session}, {"ack_sequence", ack},
                   {"accepted", accepted},  {"duplicates", duplicates},
                   {"coverage_gaps", gaps}, {"acknowledged_at", formatUtc(utcNow())}};
    store.call({{"op", "put"}, {"table", "settings"}, {"key", key}, {"data", result}});
    if (!gaps.empty())
        store.call({{"op", "audit"},
                    {"author", "mTLS agent " + enrollment.at("agent_id").get<std::string>()},
                    {"data", {{"operation", "remote_sequence_gap"}, {"host_id", host}, {"gaps", gaps}}}});
    return result;
}
Json remoteRead(StoreWorker &store, const Json &request, const Json &enrollment) {
    validateEnrollment(enrollment);
    validateDocument(request);
    if (enrollment["revoked"] == true || (enrollment["role"] != "viewer" && enrollment["role"] != "admin"))
        throw std::runtime_error("certificate lacks read role");
    auto scope = enrollment.value("allowed_hosts", std::vector<std::string>{});
    auto permitted = [&](const std::string &host) {
        return enrollment["role"] == "admin" || std::find(scope.begin(), scope.end(), host) != scope.end();
    };
    auto op = request.at("op").get<std::string>();
    store.call(
        {{"op", "audit"},
         {"author", "mTLS " + enrollment.at("fingerprint").get<std::string>()},
         {"data", {{"operation", "remote_query"}, {"request", request}, {"role", enrollment["role"]}}}});
    const std::set<std::string> fields =
        op == "detail" ? std::set<std::string>{"op", "id"}
                       : std::set<std::string>{"op", "table", "filters", "limit", "offset"};
    for (auto it = request.begin(); it != request.end(); ++it)
        if (!fields.contains(it.key()))
            throw std::runtime_error("unsupported remote query field");
    if (op == "detail") {
        auto result = store.call(request);
        if (!permitted(result.at("host_id")))
            throw std::runtime_error("host is outside reader certificate scope");
        return result;
    }
    if (op != "query" ||
        !std::set<std::string>{"hosts", "sessions", "events", "incidents", "processes", "artifacts"}.contains(
            request.at("table").get<std::string>()))
        throw std::runtime_error("remote API exposes read-only evidence queries");
    auto filters = request.value("filters", Json::object());
    auto host = filters.value("host", std::string{});
    if (enrollment["role"] != "admin" && (host.empty() || !permitted(host)))
        throw std::runtime_error("viewer query requires an explicitly authorized host");
    return store.call(request);
}
} // namespace irforge
