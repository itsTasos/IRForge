#include "irforge/reporting/ReportExporter.hpp"
#include "irforge/monitoring/Win32.hpp"
#include "irforge/reporting/Evidence.hpp"
#include <bcrypt.h>
#include <fstream>
#include <set>
namespace irforge {
namespace {
std::string filenameUtf8(const std::string &path) {
    auto bytes = filesystemPath(path).filename().u8string();
    return {bytes.begin(), bytes.end()};
}
std::string observableUuid(const Json &object) {
    auto properties = object;
    properties.erase("type");
    const std::array<unsigned char, 16> ns = {0x00, 0xab, 0xed, 0xb4, 0xaa, 0x42, 0x46, 0x6c,
                                              0x9c, 0x01, 0xfe, 0xd2, 0x33, 0x15, 0xa9, 0xb7};
    auto wire = properties.dump();
    std::vector<unsigned char> bytes(ns.begin(), ns.end());
    bytes.insert(bytes.end(), wire.begin(), wire.end());
    BCRYPT_ALG_HANDLE algorithm{};
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA1_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("UUIDv5 SHA1 provider unavailable");
    struct Cleanup {
        BCRYPT_ALG_HANDLE h;
        ~Cleanup() { BCryptCloseAlgorithmProvider(h, 0); }
    } cleanup{algorithm};
    std::array<unsigned char, 20> hash{};
    if (BCryptHash(algorithm, nullptr, 0, bytes.data(), static_cast<ULONG>(bytes.size()), hash.data(),
                   hash.size()) < 0)
        throw std::runtime_error("UUIDv5 hash failed");
    hash[6] = (hash[6] & 15) | 0x50;
    hash[8] = (hash[8] & 63) | 0x80;
    constexpr char hex[] = "0123456789abcdef";
    std::string uuid;
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            uuid += '-';
        uuid += hex[hash[i] >> 4];
        uuid += hex[hash[i] & 15];
    }
    return uuid;
}
} // namespace
std::string htmlEscape(const std::string &s) {
    std::string result;
    for (auto c : s)
        switch (c) {
        case '&':
            result += "&amp;";
            break;
        case '<':
            result += "&lt;";
            break;
        case '>':
            result += "&gt;";
            break;
        case '"':
            result += "&quot;";
            break;
        case '\'':
            result += "&#39;";
            break;
        default:
            result += c;
        }
    return result;
}
std::string csvCell(const std::string &s) {
    std::string value = s;
    auto at = value.find_first_not_of(" \t\r\n");
    if (at != std::string::npos && std::string("=+-@").find(value[at]) != std::string::npos)
        value = "'" + value;
    std::string escaped = "\"";
    for (auto c : value) {
        if (c == '"')
            escaped += '"';
        escaped += c;
    }
    return escaped + '"';
}
std::string incidentHtml(const Json &incident, const Json &context) {
    validateDocument(incident, 16 * 1048576);
    std::string html =
        "<!doctype html><html><head><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\"><title>IRForge incident "
        "report</title><style>body{font-family:Segoe "
        "UI,Arial;font-size:10pt;color:#183044;max-width:1100px;margin:40px "
        "auto;padding:24px}h1{color:#147b86}h2{border-bottom:1px solid "
        "#cad9e0;padding-top:16px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f0f5f7;padding:"
        "16px;font-family:Consolas;font-size:8pt}table{width:100%;border-collapse:collapse;font-size:10pt}td,"
        "th{padding:8px;border:1px solid "
        "#cad9e0;text-align:left}.notice{background:#e5f3f3;padding:16px}</style></head><body><h1>IRForge "
        "incident report</h1><p class='notice'>Triage priority based on observed evidence. Mapped techniques "
        "describe behavioral alignment. This report does not establish compromise.</p>";
    html += "<table><tr><th>Incident</th><td>" + htmlEscape(incident.at("incident_id").get<std::string>()) +
            "</td></tr><tr><th>Host</th><td>" + htmlEscape(incident.at("host_id").get<std::string>()) +
            "</td></tr><tr><th>Score / severity</th><td>" +
            std::to_string(incident.at("risk_score").get<int>()) + " / " +
            htmlEscape(incident.at("severity").get<std::string>()) +
            "</td></tr><tr><th>Confidence / analyst state</th><td>" +
            htmlEscape(incident.at("confidence").get<std::string>()) + " / " +
            htmlEscape(incident.at("status").get<std::string>()) + "</td></tr><tr><th>Revision</th><td>" +
            incident.value("revision", Json(1)).dump() + "</td></tr></table>";
    auto text = [](const Json &document, const std::string &key) {
        auto value = document.value(key, Json(nullptr));
        return value.is_string() ? value.get<std::string>() : value.dump();
    };
    html += "<h2>Summary</h2><p>" + htmlEscape(text(incident, "summary")) +
            "</p><p>Complete original fields, identifiers, acquisition configuration and graphs accompany "
            "this report in incident.json and export-context.json.</p>";
    html += "<h2>Distinct weighted evidence</h2><table><tr><th>Rule / points</th><th>Explanation and "
            "confidence</th></tr>";
    for (const auto &rule : incident.at("rule_matches"))
        html += "<tr><td>" + htmlEscape(text(rule, "rule_id")) + " / " + htmlEscape(text(rule, "points")) +
                "</td><td>" + htmlEscape(text(rule, "reason")) +
                "<br>Confidence: " + htmlEscape(text(rule, "confidence")) + "</td></tr>";
    html += "</table><h2>Mapped ATT&amp;CK techniques</h2>";
    if (incident.value("attack_techniques", Json::array()).empty())
        html += "<p>No mapped technique for this incident.</p>";
    for (const auto &technique : incident.value("attack_techniques", Json::array()))
        html +=
            "<p>" + htmlEscape(text(technique, "id")) + " - " + htmlEscape(text(technique, "name")) + "</p>";
    html += "<h2>Coverage gaps</h2>";
    if (incident.value("coverage_gaps", Json::array()).empty())
        html +=
            "<p>No stored gap in the selected time window. This does not establish complete collection.</p>";
    for (const auto &gap : incident.value("coverage_gaps", Json::array())) {
        auto payload = gap.value("payload", Json::object());
        auto reason = payload.value("reason", payload.value("message", std::string("See original evidence")));
        html += "<p><b>" + htmlEscape(text(gap, "source")) + "</b>: " + htmlEscape(reason) + " (" +
                htmlEscape(text(gap, "timestamp_utc")) + ")</p>";
    }
    html += "<h2>Evidence timeline</h2>";
    for (const auto &event : incident.at("timeline")) {
        html += "<p><b>" + htmlEscape(text(event, "timestamp_utc")) + " - " +
                htmlEscape(text(event, "event_type")) +
                "</b><br>Source: " + htmlEscape(text(event, "source")) + "</p>";
        auto payload = event.value("payload", Json::object());
        if (payload.contains("path"))
            html += "<p>File: " + htmlEscape(text(payload, "path")) + "</p>";
        if (payload.contains("metadata")) {
            auto metadata = payload["metadata"];
            if (metadata.contains("hash"))
                html += "<p>SHA-256: " + htmlEscape(text(metadata["hash"], "sha256")) +
                        "<br>Hash status: " + htmlEscape(text(metadata["hash"], "status")) + "</p>";
            if (metadata.contains("signature"))
                html += "<p>Signature: " + htmlEscape(text(metadata["signature"], "status")) + "</p>";
        }
        for (const auto *key : {"rule", "file", "sha256", "interpretation", "image_path", "command_line",
                                "remote_address", "remote_port"})
            if (payload.contains(key))
                html += "<p>" + htmlEscape(key) + ": " + htmlEscape(text(payload, key)) + "</p>";
    }
    html += "<h2>Relationships and analyst annotations</h2><p>Relationships retain their confidence and "
            "attribution in the accompanying evidence JSON. Unattributed writers remain unknown.</p>";
    for (const auto &note : incident.value("analyst_annotations", Json::array()))
        html += "<p>" + htmlEscape(text(note, "state")) + " - " + htmlEscape(text(note, "text")) + "</p>";
    html += "<h2>Acquisition and export context</h2><p>Acquisition mode: " +
            htmlEscape(text(incident, "acquisition_mode")) +
            "<br>Exported: " + htmlEscape(text(context, "exported_at")) +
            "<br>Source: " + htmlEscape(text(context, "source")) + "</p>";
    return html + "</body></html>";
}
Json stixBundle(const Json &incident) {
    validateDocument(incident, 16 * 1048576);
    Json objects = Json::array(), refs = Json::array();
    auto add = [&](Json j) {
        auto type = j.at("type").get<std::string>();
        auto id = type + "--" + (type == "process" ? newUuid() : observableUuid(j));
        j["id"] = id;
        j["spec_version"] = "2.1";
        if (std::find(refs.begin(), refs.end(), Json(id)) == refs.end()) {
            objects.push_back(j);
            refs.push_back(id);
        }
        return id;
    };
    std::set<std::string> seen;
    for (const auto &doc : incident.at("timeline")) {
        auto e = doc.get<SecurityEvent>();
        // A later enrichment can add a hash to an earlier path observation. Deduplicate
        // by the observable UUID, not just path, so the observed hash is retained.
        if (auto f = std::get_if<FilePayload>(&e.payload)) {
            Json file = {{"type", "file"}, {"name", filenameUtf8(f->path)}};
            if (f->metadata.contains("hash") &&
                f->metadata["hash"].value("status", std::string{}) == "complete") {
                auto digest = f->metadata["hash"].value("sha256", std::string{});
                if (digest.size() == 64)
                    file["hashes"] = {{"SHA-256", digest}};
            }
            add(file);
        }
        if (auto p = std::get_if<ProcessPayload>(&e.payload);
            p && seen.insert("process/" + identityKey(p->identity)).second) {
            Json process = {{"type", "process"}, {"pid", p->identity.pid}};
            if (p->commandLine)
                process["command_line"] = *p->commandLine;
            if (p->imagePath) {
                auto image = add({{"type", "file"}, {"name", filenameUtf8(*p->imagePath)}});
                process["image_ref"] = image;
            }
            add(process);
        }
        if (auto n = std::get_if<TcpPayload>(&e.payload);
            n && seen.insert("network/" + n->localAddress + ":" + std::to_string(n->localPort) + "/" +
                             n->remoteAddress + ":" + std::to_string(n->remotePort))
                     .second) {
            auto source = add(
                     {{"type", n->localAddress.find(':') == std::string::npos ? "ipv4-addr" : "ipv6-addr"},
                      {"value", n->localAddress.substr(0, n->localAddress.find('%'))}}),
                 destination = add(
                     {{"type", n->remoteAddress.find(':') == std::string::npos ? "ipv4-addr" : "ipv6-addr"},
                      {"value", n->remoteAddress.substr(0, n->remoteAddress.find('%'))}});
            add({{"type", "network-traffic"},
                 {"src_ref", source},
                 {"dst_ref", destination},
                 {"src_port", n->localPort},
                 {"dst_port", n->remotePort},
                 {"protocols", Json::array({n->protocol == "tcp6" ? "ipv6" : "ipv4", "tcp"})}});
        }
    }
    if (refs.empty())
        throw std::runtime_error("limited STIX export requires an observed process/file/network object");
    auto now = formatUtc(utcNow());
    auto observed = "observed-data--" + newUuid();
    objects.push_back({{"type", "observed-data"},
                       {"spec_version", "2.1"},
                       {"id", observed},
                       {"created", now},
                       {"modified", now},
                       {"first_observed", incident.at("opened_at")},
                       {"last_observed", incident.at("last_updated_at")},
                       {"number_observed", 1},
                       {"object_refs", refs}});
    objects.push_back(
        {{"type", "note"},
         {"spec_version", "2.1"},
         {"id", "note--" + newUuid()},
         {"created", now},
         {"modified", now},
         {"content", "IRForge incident " + incident.at("incident_id").get<std::string>() + ", revision " +
                         incident.value("revision", Json(1)).dump() +
                         ". Observations guide triage; no malware/attack assertion. Collector confidence: " +
                         incident.at("confidence").get<std::string>() +
                         ". STIX IP values omit native IPv6 scope IDs; original evidence retains them."},
         {"object_refs", Json::array({observed})}});
    return {{"type", "bundle"}, {"id", "bundle--" + newUuid()}, {"objects", objects}};
}
Json exportIncident(StoreWorker &store, const std::string &id, const std::string &directory,
                    const std::string &format) {
    if (!std::set<std::string>{"html", "json", "csv", "stix"}.contains(format))
        throw std::runtime_error(
            "supported formats: html/json/csv/stix; PDF is provided by the Qt report application");
    auto incident = store.call({{"op", "detail"}, {"id", id}});
    privateDirectory(directory, true);
    auto context = Json{{"case_id", id},
                        {"exported_at", formatUtc(utcNow())},
                        {"incident_revision", incident["revision"]},
                        {"health", store.call({{"op", "health"}})},
                        {"format", format},
                        {"source", "local SQLite evidence snapshot"},
                        {"application", "IRForge 1.0.0-dev"}};
    auto base = filesystemPath(directory);
    writeDocument(base / "incident.json", incident);
    writeDocument(base / "export-context.json", context);
    if (format == "html") {
        std::ofstream file(base / "report.html", std::ios::binary);
        file << incidentHtml(incident, context);
        if (!file)
            throw std::runtime_error("HTML export write failed");
    }
    if (format == "csv") {
        std::ofstream file(base / "events.csv", std::ios::binary);
        file << "event_id,timestamp_utc,event_type,source,host_id,payload\r\n";
        for (const auto &event : incident["timeline"]) {
            for (const auto *key : {"event_id", "timestamp_utc", "event_type", "source", "host_id"})
                file << csvCell(event.at(key).is_string() ? event.at(key).get<std::string>()
                                                          : event.at(key).dump())
                     << ',';
            file << csvCell(event.at("payload").dump()) << "\r\n";
        }
        if (!file)
            throw std::runtime_error("CSV export write failed");
    }
    if (format == "stix")
        writeDocument(base / "observations.stix.json", stixBundle(incident));
    writeDocument(base / "manifest.json", evidenceManifest(directory, id));
    store.call({{"op", "audit"}, {"author", "local export operator"}, {"data", context}});
    return {{"directory", directory},
            {"manifest", (base / "manifest.json").string()},
            {"revision", incident["revision"]},
            {"format", format}};
}
} // namespace irforge
