#include "irforge/ti/VirusTotal.hpp"
#include "irforge/monitoring/Win32.hpp"
#include <algorithm>
#include <cctype>
#include <charconv>
#include <set>
#ifdef _WIN32
#include <wincred.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#endif
namespace irforge {
bool VirusTotalClient::validHash(const std::string &hash) {
    return hash.size() == 64 &&
           std::all_of(hash.begin(), hash.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}
bool VirusTotalClient::publicIp(const std::string &ip) {
    if (ip.size() > 64 || addressClass(ip) != "public")
        return false;
#ifdef _WIN32
    IN_ADDR v4{};
    if (InetPtonA(AF_INET, ip.c_str(), &v4) == 1) {
        auto b = reinterpret_cast<const unsigned char *>(&v4);
        if (b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224 ||
            (b[0] == 100 && b[1] >= 64 && b[1] <= 127) || (b[0] == 169 && b[1] == 254) ||
            (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && (b[1] == 168 || b[1] == 0)) ||
            (b[0] == 192 && b[1] == 0 && b[2] == 2) || (b[0] == 198 && (b[1] == 18 || b[1] == 19)) ||
            (b[0] == 198 && b[1] == 51 && b[2] == 100) || (b[0] == 203 && b[1] == 0 && b[2] == 113))
            return false;
        return true;
    }
    IN6_ADDR v6{};
    if (InetPtonA(AF_INET6, ip.c_str(), &v6) != 1)
        return false;
    const auto *b = reinterpret_cast<const unsigned char *>(&v6);
    if (b[0] != 0x20 && b[0] != 0x26 && b[0] != 0x28 && b[0] != 0x2a && b[0] != 0x2c)
        return false;
    if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
        return false;
    return true;
#else
    return false;
#endif
}
VirusTotalClient::VirusTotalClient(StoreWorker &s, TiTransport t)
    : store_(s), productionTransport_(!t), transport_(t ? std::move(t) : virusTotalGet) {}
Json VirusTotalClient::lookup(const std::string &kind, const std::string &raw, bool opt,
                              const std::string &target, Millis now) {
    if (!opt)
        throw std::runtime_error(
            "VirusTotal lookup requires explicit opt-in; hash or public IP is disclosed to VirusTotal");
    auto value = lower(raw);
    if ((kind != "sha256" && kind != "ip") || (kind == "sha256" && !validHash(value)) ||
        (kind == "ip" && !publicIp(value)))
        throw std::runtime_error(
            "only SHA256 or public routable IP lookup supported; private/reserved IP never leaves host");
    auto key = "virustotal/" + kind + "/" + value;
    auto cache = store_.call({{"op", "get"}, {"table", "ti_cache"}, {"key", key}});
    if (!cache.is_null() && parseUtc(cache.at("expires_at").get<std::string>()) > now) {
        cache["cache_hit"] = true;
        return cache;
    }
    auto credential = productionTransport_ ? loadTiCredential(target) : std::string("test-transport-only");
    auto reservation = store_.call({{"op", "ti_reserve"}, {"now", now}});
    if (!reservation.at("allowed").get<bool>())
        return {{"status", "rate_limited"},
                {"retry_at", reservation.at("retry_at")},
                {"provider", "virustotal"},
                {"indicator", value}};
    HttpResponse response;
    try {
        response = transport_(kind == "sha256" ? "/api/v3/files/" + value : "/api/v3/ip_addresses/" + value,
                              credential);
    } catch (...) {
        std::fill(credential.begin(), credential.end(), '\0');
        store_.call({{"op", "ti_backoff"}, {"retry_at", now + 60000}});
        throw;
    }
    std::fill(credential.begin(), credential.end(), '\0');
    Json result = {{"provider", "virustotal"},
                   {"indicator", value},
                   {"kind", kind},
                   {"http_status", response.status},
                   {"fetched_at", formatUtc(now)},
                   {"expires_at", formatUtc(now + 86400000)},
                   {"verdict", "unknown"},
                   {"status", "unavailable"},
                   {"file_uploaded", false},
                   {"interpretation", "third-party reputation; no remediation decision"}};
    if (response.status == 429) {
        int seconds = 60;
        auto parsed = std::from_chars(response.retryAfter.data(),
                                      response.retryAfter.data() + response.retryAfter.size(), seconds);
        if (parsed.ec != std::errc{} || parsed.ptr != response.retryAfter.data() + response.retryAfter.size())
            seconds = 60;
        seconds = std::clamp(seconds, 60, 86400);
        store_.call({{"op", "ti_backoff"}, {"retry_at", now + seconds * 1000LL}});
        result["status"] = "rate_limited";
        result["retry_at"] = formatUtc(now + seconds * 1000LL);
        return result;
    }
    if (response.status == 401 || response.status == 403) {
        result["status"] = "credential_rejected";
        store_.call({{"op", "ti_backoff"}, {"retry_at", now + 300000}});
        return result;
    }
    if (response.status == 404) {
        result["status"] = "not_found";
        result["expires_at"] = formatUtc(now + 3600000);
    } else if (response.status == 200) {
        if (response.body.size() > 1048576)
            throw std::runtime_error("VirusTotal response exceeds size limit");
        auto document = Json::parse(response.body, [](int depth, Json::parse_event_t, Json &) {
            if (depth > 32)
                throw std::runtime_error("TI JSON nesting exceeds 32");
            return true;
        });
        validateDocument(document);
        const auto &data = document.at("data");
        if (lower(data.at("id").get<std::string>()) != value)
            throw std::runtime_error("VirusTotal returned a different indicator");
        auto attributes = data.at("attributes");
        Json stats = attributes.value("last_analysis_stats", Json::object());
        if (!stats.is_object() || stats.size() > 32)
            throw std::runtime_error("invalid VirusTotal statistics");
        int malicious = 0;
        for (auto it = stats.begin(); it != stats.end(); ++it) {
            if (!it.value().is_number_integer() || it.value().get<int>() < 0 ||
                it.value().get<int>() > 100000)
                throw std::runtime_error("invalid reputation count");
            if (it.key() == "malicious")
                malicious = it.value().get<int>();
        }
        result["status"] = "complete";
        result["verdict"] = malicious > 0 ? "provider_detections" : "no_provider_detections";
        result["response"] = {{"last_analysis_stats", stats},
                              {"reputation", attributes.value("reputation", Json(nullptr))},
                              {"last_analysis_date", attributes.value("last_analysis_date", Json(nullptr))}};
    } else {
        if (response.status >= 500)
            store_.call({{"op", "ti_backoff"}, {"retry_at", now + 60000}});
        return result;
    }
    auto expires = parseUtc(result.at("expires_at").get<std::string>());
    store_.call(
        {{"op", "put"}, {"table", "ti_cache"}, {"key", key}, {"data", result}, {"expires_ms", expires}});
    store_.call({{"op", "audit"},
                 {"author", "explicit local TI operator"},
                 {"data",
                  {{"operation", "virustotal_lookup"},
                   {"indicator", value},
                   {"kind", kind},
                   {"http_status", response.status},
                   {"file_uploaded", false}}}});
    return result;
}
#ifdef _WIN32
namespace {
void targetCheck(const std::string &s) {
    if (s.empty() || s.size() > 128 ||
        s.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_") !=
            std::string::npos)
        throw std::runtime_error("invalid credential target");
}
struct Internet {
    HINTERNET h{};
    explicit Internet(HINTERNET v) : h(v) {
        if (!h)
            throw WindowsError(GetLastError(), "WinHTTP handle");
    }
    ~Internet() { WinHttpCloseHandle(h); }
    Internet(const Internet &) = delete;
};
std::string header(HINTERNET request, DWORD name) {
    DWORD n = 0;
    WinHttpQueryHeaders(request, name, nullptr, nullptr, &n, nullptr);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || n > 8192)
        return {};
    std::vector<wchar_t> text(n / sizeof(wchar_t) + 1);
    if (!WinHttpQueryHeaders(request, name, nullptr, text.data(), &n, nullptr))
        return {};
    return utf8(text.data());
}
} // namespace
void saveTiCredential(const std::string &target, const std::string &key) {
    targetCheck(target);
    if (key.size() < 16 || key.size() > 1024 ||
        key.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=") !=
            std::string::npos)
        throw std::runtime_error("invalid API credential format");
    auto name = utf16(target);
    CREDENTIALW credential{};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = name.data();
    credential.CredentialBlobSize = static_cast<DWORD>(key.size());
    credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char *>(key.data()));
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    credential.UserName = const_cast<wchar_t *>(L"IRForge opt-in VirusTotal");
    if (!CredWriteW(&credential, 0))
        throw WindowsError(GetLastError(), "Credential Manager write");
}
std::string loadTiCredential(const std::string &target) {
    targetCheck(target);
    PCREDENTIALW credential{};
    if (!CredReadW(utf16(target).c_str(), CRED_TYPE_GENERIC, 0, &credential))
        throw WindowsError(GetLastError(), "VirusTotal credential unavailable for this Windows account");
    std::string key(reinterpret_cast<char *>(credential->CredentialBlob), credential->CredentialBlobSize);
    CredFree(credential);
    return key;
}
void removeTiCredential(const std::string &target) {
    targetCheck(target);
    if (!CredDeleteW(utf16(target).c_str(), CRED_TYPE_GENERIC, 0) && GetLastError() != ERROR_NOT_FOUND)
        throw WindowsError(GetLastError(), "Credential Manager removal");
}
HttpResponse virusTotalGet(const std::string &path, const std::string &key) {
    if (!path.starts_with("/api/v3/files/") && !path.starts_with("/api/v3/ip_addresses/"))
        throw std::runtime_error("VirusTotal endpoint allowlist rejected");
    Internet session(WinHttpOpen(L"IRForge/1.0 metadata-reputation", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    WinHttpSetTimeouts(session.h, 5000, 5000, 5000, 5000);
    Internet connection(WinHttpConnect(session.h, L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, 0));
    Internet request(WinHttpOpenRequest(connection.h, L"GET", utf16(path).c_str(), nullptr,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        WINHTTP_FLAG_SECURE));
    DWORD redirects = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    WinHttpSetOption(request.h, WINHTTP_OPTION_REDIRECT_POLICY, &redirects, sizeof(redirects));
    auto headers = L"x-apikey: " + utf16(key) + L"\r\nAccept: application/json\r\n";
    if (!WinHttpSendRequest(request.h, headers.c_str(), static_cast<DWORD>(headers.size()),
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request.h, nullptr))
        throw WindowsError(GetLastError(), "VirusTotal GET");
    HttpResponse response;
    DWORD status = 0, n = sizeof(status);
    if (!WinHttpQueryHeaders(request.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr,
                             &status, &n, nullptr))
        throw WindowsError(GetLastError(), "VirusTotal status");
    response.status = static_cast<int>(status);
    response.retryAfter = header(request.h, WINHTTP_QUERY_RETRY_AFTER);
    const auto bodyDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    for (;;) {
        if (std::chrono::steady_clock::now() >= bodyDeadline)
            throw std::runtime_error("VirusTotal response deadline exceeded");
        DWORD bytes = 0;
        if (!WinHttpQueryDataAvailable(request.h, &bytes))
            throw WindowsError(GetLastError(), "VirusTotal response availability");
        if (!bytes)
            break;
        if (response.body.size() + bytes > 1048576)
            throw std::runtime_error("VirusTotal response budget exceeded");
        auto at = response.body.size();
        response.body.resize(at + bytes);
        DWORD read = 0;
        if (!WinHttpReadData(request.h, response.body.data() + at, bytes, &read))
            throw WindowsError(GetLastError(), "VirusTotal response read");
        response.body.resize(at + read);
        if (!read)
            break;
    }
    return response;
}
#else
void saveTiCredential(const std::string &, const std::string &) {
    throw std::runtime_error("Windows credentials required");
}
std::string loadTiCredential(const std::string &) {
    throw std::runtime_error("Windows credentials required");
}
void removeTiCredential(const std::string &) { throw std::runtime_error("Windows credentials required"); }
HttpResponse virusTotalGet(const std::string &, const std::string &) {
    throw std::runtime_error("WinHTTP required");
}
#endif
Json parseIocCsv(const std::string &text, const std::string &source) {
    if (text.size() > 1048576)
        throw std::runtime_error("IOC CSV exceeds 1 MiB");
    std::vector<std::vector<std::string>> records;
    std::vector<std::string> record;
    std::string field;
    bool quoted = false, closed = false;
    auto endField = [&] {
        if (field.size() > 4096)
            throw std::runtime_error("IOC CSV field exceeds bound");
        record.push_back(field);
        field.clear();
        closed = false;
        if (record.size() > 4)
            throw std::runtime_error("IOC CSV column bound");
    };
    auto endRecord = [&] {
        endField();
        if (!(record.size() == 1 && record[0].empty()))
            records.push_back(record);
        record.clear();
        if (records.size() > 5001)
            throw std::runtime_error("IOC CSV row bound");
    };
    for (std::size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        if (quoted) {
            if (c == '"') {
                if (i + 1 < text.size() && text[i + 1] == '"') {
                    field += '"';
                    ++i;
                } else {
                    quoted = false;
                    closed = true;
                }
            } else
                field += c;
        } else if (c == '"' && field.empty() && !closed)
            quoted = true;
        else if (c == ',')
            endField();
        else if (c == '\n')
            endRecord();
        else if (c == '\r' && i + 1 < text.size() && text[i + 1] == '\n') {
            endRecord();
            ++i;
        } else {
            if (closed || c == '"' || c == '\0')
                throw std::runtime_error("malformed IOC CSV quoting");
            field += c;
        }
        if (field.size() > 4096)
            throw std::runtime_error("IOC CSV field bound");
    }
    if (quoted)
        throw std::runtime_error("unterminated IOC CSV quote");
    if (!field.empty() || !record.empty() || closed)
        endRecord();
    const std::vector<std::string> header = {"kind", "value", "label", "expires_at"};
    if (records.empty() || records[0] != header)
        throw std::runtime_error("IOC CSV header must be kind,value,label,expires_at");
    Json feed = {
        {"schema_version", 1}, {"reviewed", true}, {"source", source}, {"indicators", Json::array()}};
    for (std::size_t i = 1; i < records.size(); ++i) {
        if (records[i].size() != 4)
            throw std::runtime_error("IOC CSV row needs four fields");
        Json row = {{"kind", records[i][0]}, {"value", records[i][1]}, {"label", records[i][2]}};
        if (!records[i][3].empty())
            row["expires_at"] = records[i][3];
        feed["indicators"].push_back(row);
    }
    return IocMatcher(feed).feed();
}
IocMatcher::IocMatcher(Json feed) : feed_(std::move(feed)) {
    validateDocument(feed_);
    if (feed_.at("schema_version") != 1 || !feed_.at("reviewed").get<bool>() ||
        !feed_.at("indicators").is_array() || feed_["indicators"].size() > 5000 ||
        feed_.value("source", std::string{}).empty())
        throw std::runtime_error("IOC feed requires bounded reviewed source/version");
    Json distinct = Json::array();
    std::set<std::string> seen;
    for (const auto &row : feed_["indicators"]) {
        auto kind = row.at("kind").get<std::string>(), value = row.at("value").get<std::string>();
        if (kind == "sha256") {
            if (!VirusTotalClient::validHash(value))
                throw std::runtime_error("invalid IOC SHA256");
        } else if (kind == "ip") {
            if (addressClass(value) == "invalid")
                throw std::runtime_error("invalid IOC IP");
        } else if (kind == "cidr") {
            auto slash = value.find('/');
            unsigned bits = 0;
            if (slash == std::string::npos)
                throw std::runtime_error("invalid IOC CIDR");
            auto prefix = value.substr(slash + 1);
            auto p = std::from_chars(prefix.data(), prefix.data() + prefix.size(), bits);
            if (p.ec != std::errc{} || p.ptr != prefix.data() + prefix.size() ||
                addressClass(value.substr(0, slash)) == "invalid" ||
                bits > (value.find(':') == std::string::npos ? 32u : 128u))
                throw std::runtime_error("invalid IOC prefix");
        } else
            throw std::runtime_error("only SHA256/IP/CIDR local IOCs supported");
        if (row.value("label", std::string{}).size() > 1024)
            throw std::runtime_error("IOC label too long");
        if (row.contains("expires_at"))
            (void)parseUtc(row["expires_at"].get<std::string>());
        if (seen.insert(row.dump()).second)
            distinct.push_back(row);
    }
    feed_["indicators"] = std::move(distinct);
}
Json IocMatcher::match(const std::string &kind, const std::string &value, Millis now) const {
    Json result = Json::array();
    for (const auto &row : feed_["indicators"]) {
        if (row.contains("expires_at") && parseUtc(row["expires_at"].get<std::string>()) <= now)
            continue;
        auto type = row.at("kind").get<std::string>();
        bool matches = type == kind && lower(row.at("value").get<std::string>()) == lower(value);
#ifdef _WIN32
        if (type == "cidr" && kind == "ip") {
            auto cidr = row.at("value").get<std::string>();
            auto slash = cidr.find('/');
            int family = cidr.find(':') == std::string::npos ? AF_INET : AF_INET6;
            unsigned bits = static_cast<unsigned>(std::stoul(cidr.substr(slash + 1)));
            unsigned char network[16]{}, address[16]{};
            if (InetPtonA(family, cidr.substr(0, slash).c_str(), network) == 1 &&
                InetPtonA(family, value.c_str(), address) == 1) {
                matches = true;
                for (unsigned i = 0; i < bits; ++i)
                    if ((network[i / 8] & (0x80 >> (i % 8))) != (address[i / 8] & (0x80 >> (i % 8)))) {
                        matches = false;
                        break;
                    }
            }
        }
#endif
        if (matches) {
            auto match = row;
            match["source"] = feed_.at("source");
            match["interpretation"] = "reviewed local IOC context; not a remediation verdict";
            result.push_back(match);
        }
    }
    return result;
}
} // namespace irforge
