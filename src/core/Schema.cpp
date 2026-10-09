#include "irforge/core/Schema.hpp"
#include "irforge/detection/AttackMapper.hpp"
#include <functional>
#include <iomanip>
#include <random>
#include <set>
#include <sstream>
#ifdef _WIN32
#include <objbase.h>
#include <windows.h>
#endif
namespace irforge {
std::string newUuid() {
#ifdef _WIN32
    GUID g{};
    if (FAILED(CoCreateGuid(&g)))
        throw std::runtime_error("CoCreateGuid failed");
    wchar_t text[40]{};
    StringFromGUID2(g, text, 40);
    auto s = lower(utf8(text));
    return s.substr(1, s.size() - 2);
#else
    std::random_device r;
    std::ostringstream s;
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            s << '-';
        unsigned b = r() & 255;
        if (i == 6)
            b = (b & 15) | 64;
        if (i == 8)
            b = (b & 63) | 128;
        s << std::hex << std::setw(2) << std::setfill('0') << b;
    }
    return s.str();
#endif
}
std::string stableHostId() {
#ifdef _WIN32
    wchar_t value[256]{};
    DWORD n = sizeof(value);
    auto code = RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
                             RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, value, &n);
    if (code != ERROR_SUCCESS)
        throw std::runtime_error("MachineGuid unavailable: " + std::to_string(code));
    return lower(utf8(value));
#else
    throw std::runtime_error("stable machine identity requires Windows");
#endif
}
void validateDocument(const Json &j, std::size_t maxBytes) {
    if (!j.is_object() || j.dump().size() > maxBytes)
        throw std::runtime_error("document must be a bounded object");
    std::function<void(const Json &, int)> walk = [&](const Json &v, int d) {
        if (d > 32)
            throw std::runtime_error("document nesting exceeds 32");
        if (v.is_string() && v.get_ref<const std::string &>().size() > 262144)
            throw std::runtime_error("string exceeds limit");
        if (v.is_structured()) {
            if (v.size() > 10000)
                throw std::runtime_error("container exceeds limit");
            for (auto &x : v)
                walk(x, d + 1);
        }
    };
    walk(j, 0);
}
Json upgradeEvent(const Json &j, const std::string &host, const std::string &session) {
    validateDocument(j);
    auto e = j.get<SecurityEvent>();
    if (e.schemaVersion == 2)
        return j;
    e.schemaVersion = 2;
    e.hostId = host;
    e.sessionId = session;
    e.observedAtUtc = e.timestampUtc;
    e.uniqueId = host + "/" + session + "/" + std::to_string(e.id);
    if (auto p = std::get_if<ProcessPayload>(&e.payload)) {
        e.attributionMethod =
            p->identity.creationTime100ns ? "verified_creation_time" : "observed_generation";
        e.attributionConfidence = p->identity.creationTime100ns ? "high" : "low";
    } else if (auto n = std::get_if<TcpPayload>(&e.payload)) {
        e.attributionMethod = "observed_owner_pid";
        e.attributionConfidence = n->ownerCreationTime100ns ? "high" : "low";
    } else if (std::holds_alternative<RegistryPayload>(e.payload)) {
        e.attributionMethod = "unattributed_registry_diff";
        e.missingData.push_back("registry_writer");
    }
    return Json(e);
}
std::string observationDedupKey(const SecurityEvent &e) {
    if (auto p = std::get_if<ProcessPayload>(&e.payload); p && p->identity.creationTime100ns)
        return e.hostId + "/" + eventTypeName(e.type) + "/" + std::to_string(p->identity.pid) + "/" +
               std::to_string(*p->identity.creationTime100ns);
    if (!e.sourceRecordId.empty())
        return e.hostId + "/record/" + e.source + "/" + e.sourceRecordId;
    return e.uniqueId.empty() ? e.host + "/event/" + std::to_string(e.id) : e.uniqueId;
}
Json incidentV2(const Incident &i, const std::string &host, const std::string &session) {
    auto j = incidentJson(i);
    j["schema_version"] = 2;
    j["host_id"] = host;
    j["session_id"] = session;
    j["analysis_state"] = i.status;
    j["status"] = "new";
    j["opened_at"] = j["first_seen_utc"];
    j["last_updated_at"] = j["last_seen_utc"];
    j["risk_score"] = i.score;
    j["title"] = "Observed behavioral evidence";
    j["summary"] = "Triage priority; not a compromise verdict.";
    j["rule_matches"] = j["matched_rules"];
    j["related_processes"] = j["linked_process_identities"];
    j["evidence_event_ids"] = j["event_ids"];
    j["score_explanation"] = j["matched_rules"];
    j["relationships"] = Json::array();
    j["timeline"] = Json::array();
    j["attack_techniques"] = Json::array();
    std::set<std::string> mapped;
    for (const auto &match : i.matches)
        for (const auto &id : match.attack)
            if (mapped.insert(id).second) {
                auto row = AttackMapper::technique(id);
                row["interpretation"] = "mapped technique; behavioral alignment only";
                j["attack_techniques"].push_back(row);
            }
    j["analyst_annotations"] = Json::array();
    j["coverage_gaps"] = Json::array();
    j["provenance"] = {{"analysis", "irforge"},
                       {"registry_writer", "unknown unless explicitly supplied by provider"}};
    return j;
}
} // namespace irforge
