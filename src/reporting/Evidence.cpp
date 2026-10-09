#include "irforge/reporting/Evidence.hpp"
#include "irforge/core/Schema.hpp"
#include "irforge/enrichment/HashEngine.hpp"
#include "irforge/monitoring/InventoryMonitor.hpp"
#include <algorithm>
#include <fstream>
#include <set>
#ifdef _WIN32
#include "irforge/monitoring/Win32.hpp"
#include <sddl.h>
#include <winevt.h>
#endif
namespace irforge {
namespace {
std::string textPath(const std::filesystem::path &p) {
    auto s = p.u8string();
    return {s.begin(), s.end()};
}
std::vector<std::filesystem::path> evidenceFiles(const std::filesystem::path &root) {
    std::vector<std::filesystem::path> files;
    for (auto &entry : std::filesystem::directory_iterator(root))
        if (entry.is_regular_file() && entry.path().filename() != "evidence_manifest.json" &&
            entry.path().extension() != ".zip") {
            if (entry.is_symlink())
                throw std::runtime_error("symlink evidence excluded");
            files.push_back(entry.path());
        }
    std::sort(files.begin(), files.end());
    if (files.size() > 128)
        throw std::runtime_error("evidence file count exceeds 128");
    return files;
}
std::uint32_t crc32(std::span<const std::uint8_t> bytes) {
    std::uint32_t crc = 0xffffffff;
    for (auto byte : bytes) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
    return ~crc;
}
void word(std::ostream &s, std::uint16_t value) {
    s.put(static_cast<char>(value & 255));
    s.put(static_cast<char>(value >> 8));
}
void dword(std::ostream &s, std::uint32_t value) {
    word(s, static_cast<std::uint16_t>(value));
    word(s, static_cast<std::uint16_t>(value >> 16));
}
} // namespace
void privateDirectory(const std::string &directory, bool requireEmpty) {
    auto root = filesystemPath(directory);
    if (std::filesystem::is_symlink(root) ||
        (std::filesystem::exists(root) &&
         (!std::filesystem::is_directory(root) || (requireEmpty && !std::filesystem::is_empty(root)))))
        throw std::runtime_error("output must be a fresh private directory");
    std::filesystem::create_directories(root);
#ifdef _WIN32
    Handle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value))
        throw WindowsError(GetLastError(), "output token");
    DWORD size = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
    std::vector<std::uint8_t> buffer(size);
    if (!GetTokenInformation(token.value, TokenUser, buffer.data(), size, &size))
        throw WindowsError(GetLastError(), "output identity");
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid, &sid))
        throw WindowsError(GetLastError(), "output SID");
    std::wstring sddl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + std::wstring(sid) + L")";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr))
        throw WindowsError(GetLastError(), "output descriptor");
    BOOL ok =
        SetFileSecurityW(root.c_str(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
    DWORD error = ok ? 0 : GetLastError();
    LocalFree(sd);
    winCheck(error, "private evidence directory");
#else
    std::filesystem::permissions(root, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
#endif
}
void writeDocument(const std::filesystem::path &path, const Json &j) {
    validateDocument(j, 64 * 1024 * 1024);
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << j.dump(2) << '\n';
    file.flush();
    if (!file)
        throw std::runtime_error("evidence write failed: " + textPath(path));
}
Json evidenceManifest(const std::string &directory, const std::string &caseId, std::uint64_t maxBytes) {
    auto root = filesystemPath(directory);
    Json entries = Json::array();
    std::uint64_t total = 0;
    for (auto &p : evidenceFiles(root)) {
        auto size = std::filesystem::file_size(p);
        if (size > maxBytes - total)
            throw std::runtime_error("case exceeds evidence byte budget");
        total += size;
        auto hash = hashFile(textPath(p), maxBytes);
        if (hash.status != "complete")
            throw std::runtime_error("Cannot manifest incomplete file hash: " + textPath(p));
        entries.push_back({{"path", textPath(p.filename())}, {"bytes", size}, {"sha256", hash.sha256}});
    }
    Json result = {{"schema_version", 1},   {"case_id", caseId},
                   {"algorithm", "sha256"}, {"acquired_at_utc", formatUtc(utcNow())},
                   {"files", entries},      {"total_bytes", total}};
    writeDocument(root / "evidence_manifest.json", result);
    return result;
}
Json verifyEvidence(const std::string &path) {
    auto j = readJsonFile(path);
    if (j.at("schema_version") != 1 || j.at("algorithm") != "sha256" || !j.at("files").is_array() ||
        j["files"].size() > 128)
        throw std::runtime_error("unsupported evidence manifest");
    auto root = std::filesystem::absolute(filesystemPath(path)).parent_path();
    Json errors = Json::array();
    std::set<std::string> names;
    for (auto &entry : j["files"]) {
        auto name = entry.at("path").get<std::string>();
        auto relative = filesystemPath(name);
        if (name.empty() || relative.is_absolute() || relative.has_parent_path() ||
            name.find(':') != std::string::npos || !names.insert(name).second)
            throw std::runtime_error("unsafe or duplicate manifest filename");
        auto file = root / relative;
        auto expected = entry.at("sha256").get<std::string>();
        if (expected.size() != 64 || expected.find_first_not_of("0123456789abcdef") != std::string::npos)
            throw std::runtime_error("invalid SHA256 in manifest");
        if (!pathWithinRoot(textPath(file), textPath(root))) {
            errors.push_back({{"path", name}, {"reason", "missing_or_outside_root"}});
            continue;
        }
        auto r = hashFile(textPath(file), 64ULL * 1024 * 1024);
        if (r.status != "complete" || r.sha256 != expected ||
            r.bytes != entry.at("bytes").get<std::uint64_t>())
            errors.push_back({{"path", name}, {"reason", "integrity_mismatch"}, {"hash_status", r.status}});
    }
    return {{"valid", errors.empty()}, {"checked", j["files"].size()}, {"errors", errors}};
}
void zipEvidence(const std::string &directory, const std::string &zip, std::uint64_t maxBytes) {
    auto root = filesystemPath(directory);
    auto files = evidenceFiles(root);
    if (std::filesystem::exists(root / "evidence_manifest.json"))
        files.push_back(root / "evidence_manifest.json");
    if (std::filesystem::exists(filesystemPath(zip)))
        throw std::runtime_error("ZIP output already exists");
    std::ofstream out(filesystemPath(zip), std::ios::binary);
    if (!out)
        throw std::runtime_error("cannot create ZIP");
    struct Central {
        std::string name;
        std::uint32_t crc, size, offset;
    };
    std::vector<Central> central;
    std::uint64_t total = 0;
    for (auto &file : files) {
        auto n = std::filesystem::file_size(file);
        if (n > maxBytes - total || n > UINT32_MAX)
            throw std::runtime_error("ZIP byte budget exceeded");
        total += n;
        std::ifstream in(file, std::ios::binary);
        std::vector<std::uint8_t> data(static_cast<std::size_t>(n));
        in.read(reinterpret_cast<char *>(data.data()), static_cast<std::streamsize>(n));
        if (!in && n)
            throw std::runtime_error("ZIP input changed/unavailable");
        auto name = textPath(file.filename());
        Central c{name, crc32(data), static_cast<std::uint32_t>(n), static_cast<std::uint32_t>(out.tellp())};
        central.push_back(c);
        dword(out, 0x04034b50);
        word(out, 20);
        word(out, 0x0800);
        word(out, 0);
        word(out, 0);
        word(out, 0x0021);
        dword(out, c.crc);
        dword(out, c.size);
        dword(out, c.size);
        word(out, static_cast<std::uint16_t>(name.size()));
        word(out, 0);
        out << name;
        out.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(n));
    }
    auto offset = static_cast<std::uint32_t>(out.tellp());
    for (auto &c : central) {
        dword(out, 0x02014b50);
        word(out, 20);
        word(out, 20);
        word(out, 0x0800);
        word(out, 0);
        word(out, 0);
        word(out, 0x0021);
        dword(out, c.crc);
        dword(out, c.size);
        dword(out, c.size);
        word(out, static_cast<std::uint16_t>(c.name.size()));
        word(out, 0);
        word(out, 0);
        word(out, 0);
        word(out, 0);
        dword(out, 0);
        dword(out, c.offset);
        out << c.name;
    }
    auto bytes = static_cast<std::uint32_t>(out.tellp()) - offset;
    dword(out, 0x06054b50);
    word(out, 0);
    word(out, 0);
    word(out, static_cast<std::uint16_t>(central.size()));
    word(out, static_cast<std::uint16_t>(central.size()));
    dword(out, bytes);
    dword(out, offset);
    word(out, 0);
    out.flush();
    if (!out)
        throw std::runtime_error("ZIP output failed");
}
Json forensicSnapshot(const std::string &output, bool includeEvtx, const Json &health,
                      const Json &artifacts) {
#ifdef _WIN32
    privateDirectory(output);
    auto root = filesystemPath(output);
    auto started = utcNow();
    auto id = newUuid();
    Json gaps = Json::array();
    Json context = {{"schema_version", 1},
                    {"case_id", id},
                    {"mode", "on_demand_snapshot"},
                    {"host_id", stableHostId()},
                    {"start_utc", formatUtc(started)},
                    {"raw_private_files_copied", false},
                    {"include_evtx", includeEvtx}};
    writeDocument(root / "processes.json", inventoryProcesses());
    writeDocument(root / "sockets.json", inventorySockets());
    Json persistence = Json::object();
    for (auto pair :
         std::vector<std::pair<std::string, InventoryResult>>{{"services", inventoryServices()},
                                                              {"tasks", inventoryTasks()},
                                                              {"startup", inventoryStartup()},
                                                              {"registry", inventoryExtendedRegistry()}}) {
        persistence[pair.first] = {
            {"complete", pair.second.complete}, {"entries", pair.second.entries}, {"gaps", pair.second.gaps}};
        for (auto &gap : pair.second.gaps)
            gaps.push_back(gap);
    }
    writeDocument(root / "persistence.json", persistence);
    writeDocument(
        root / "artifacts.json",
        {{"rows", artifacts}, {"source", "previously collected metadata; no implicit whole-drive scan"}});
    writeDocument(root / "monitor-health.json",
                  health.empty() ? Json{{"state", "snapshot_only"}, {"live_collection_active", false}}
                                 : health);
    if (includeEvtx)
        for (auto channel : {"System", "Security", "Microsoft-Windows-Sysmon/Operational"}) {
            auto file = root / (std::string(channel) == "System"     ? "system.evtx"
                                : std::string(channel) == "Security" ? "security.evtx"
                                                                     : "sysmon.evtx");
            if (!EvtExportLog(nullptr, utf16(channel).c_str(),
                              L"*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]", file.c_str(),
                              EvtExportLogChannelPath))
                gaps.push_back(std::string(channel) + ": EVTX export error " +
                               std::to_string(GetLastError()));
            else if (std::filesystem::file_size(file) > 16ULL * 1024 * 1024) {
                std::filesystem::remove(file);
                gaps.push_back(std::string(channel) + ": EVTX export exceeds 16 MiB; omitted");
            }
        }
    context["stop_utc"] = formatUtc(utcNow());
    context["known_gaps"] = gaps;
    writeDocument(root / "host-summary.json", context);
    auto manifest = evidenceManifest(output, id);
    zipEvidence(output, output + "/snapshot.zip");
    return {{"case_id", id}, {"directory", output}, {"manifest", manifest}, {"known_gaps", gaps}};
#else
    (void)output;
    (void)includeEvtx;
    (void)health;
    (void)artifacts;
    throw std::runtime_error("snapshot requires Windows");
#endif
}
} // namespace irforge
