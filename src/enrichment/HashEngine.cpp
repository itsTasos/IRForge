#include "irforge/enrichment/HashEngine.hpp"
#include "irforge/monitoring/Win32.hpp"
#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>
#ifdef _WIN32
#include <bcrypt.h>
#include <shlobj.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#endif
namespace irforge {
#ifdef _WIN32
namespace {
std::string hex(std::span<const std::uint8_t> data) {
    std::ostringstream s;
    s << std::hex << std::setfill('0');
    for (auto b : data)
        s << std::setw(2) << static_cast<unsigned>(b);
    return s.str();
}
void cryptoCheck(NTSTATUS s) {
    if (s < 0)
        throw std::runtime_error("CNG status " + std::to_string(static_cast<std::uint32_t>(s)));
}
struct CngHash {
    BCRYPT_ALG_HANDLE alg{};
    BCRYPT_HASH_HANDLE hash{};
    CngHash() {
        cryptoCheck(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0));
        try {
            cryptoCheck(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0));
        } catch (...) {
            BCryptCloseAlgorithmProvider(alg, 0);
            throw;
        }
    }
    ~CngHash() {
        if (hash)
            BCryptDestroyHash(hash);
        if (alg)
            BCryptCloseAlgorithmProvider(alg, 0);
    }
    void update(std::span<const std::uint8_t> bytes) {
        if (bytes.size() > ULONG_MAX)
            throw std::runtime_error("hash chunk too large");
        cryptoCheck(
            BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0));
    }
    std::string finish() {
        std::array<std::uint8_t, 32> digest{};
        cryptoCheck(BCryptFinishHash(hash, digest.data(), digest.size(), 0));
        return hex(digest);
    }
};
Json metadata(HANDLE h) {
    BY_HANDLE_FILE_INFORMATION i{};
    if (!GetFileInformationByHandle(h, &i))
        throw WindowsError(GetLastError(), "file metadata");
    return {{"volume_serial", i.dwVolumeSerialNumber},
            {"file_index", (static_cast<std::uint64_t>(i.nFileIndexHigh) << 32) | i.nFileIndexLow},
            {"size", (static_cast<std::uint64_t>(i.nFileSizeHigh) << 32) | i.nFileSizeLow},
            {"last_write_100ns", filetimeValue(i.ftLastWriteTime)},
            {"creation_time_100ns", filetimeValue(i.ftCreationTime)},
            {"attributes", i.dwFileAttributes}};
}
std::string finalPath(HANDLE h) {
    DWORD n = GetFinalPathNameByHandleW(h, nullptr, 0, FILE_NAME_NORMALIZED);
    if (!n || n > 32768)
        throw WindowsError(GetLastError(), "final file path");
    std::wstring p(n, L'\0');
    auto r = GetFinalPathNameByHandleW(h, p.data(), n, FILE_NAME_NORMALIZED);
    if (!r || r >= n)
        throw WindowsError(GetLastError(), "final file path");
    p.resize(r);
    return normalizePath(utf8(p));
}
} // namespace
std::string sha256Bytes(std::span<const std::uint8_t> bytes) {
    CngHash hash;
    hash.update(bytes);
    return hash.finish();
}
std::string expandWindowsPath(const std::string &input) {
    if (input == "known:Startup" || input == "known:CommonStartup" || input == "known:Downloads") {
        const KNOWNFOLDERID &id = input == "known:Startup"         ? FOLDERID_Startup
                                  : input == "known:CommonStartup" ? FOLDERID_CommonStartup
                                                                   : FOLDERID_Downloads;
        PWSTR p = nullptr;
        auto hr = SHGetKnownFolderPath(id, KF_FLAG_DONT_VERIFY, nullptr, &p);
        if (FAILED(hr))
            throw std::runtime_error("Known Folder lookup failed: " + std::to_string(hr));
        std::wstring path = p;
        CoTaskMemFree(p);
        return utf8(path);
    }
    auto w = utf16(input);
    DWORD n = ExpandEnvironmentStringsW(w.c_str(), nullptr, 0);
    if (!n || n > 32768)
        throw std::runtime_error("expanded root exceeds supported path size");
    std::wstring expanded(n, L'\0');
    if (!ExpandEnvironmentStringsW(w.c_str(), expanded.data(), n))
        throw WindowsError(GetLastError(), "expand watch root");
    expanded.resize(n - 1);
    auto result = utf8(expanded);
    if (result.find('%') != std::string::npos)
        throw std::runtime_error("unresolved environment variable in path");
    return result;
}
Json pathBoundaryCheck(const std::string &path, const std::string &root, bool missing) {
    try {
        auto wr = utf16(root), wp = utf16(path);
        Handle rh(CreateFileW(wr.c_str(), FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        if (!rh.value || rh.value == INVALID_HANDLE_VALUE)
            return {{"allowed", false}, {"operation", "open_root"}, {"error", GetLastError()}};
        auto base = finalPath(rh.value);
        auto candidate = filesystemPath(path);
        if (missing && !std::filesystem::exists(candidate))
            candidate = candidate.parent_path();
        Handle fh(CreateFileW(candidate.c_str(), FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        if (!fh.value || fh.value == INVALID_HANDLE_VALUE)
            return {{"allowed", false}, {"operation", "open_candidate"}, {"error", GetLastError()}};
        auto actual = finalPath(fh.value);
        return {{"allowed", actual == base || actual.starts_with(base + "\\")},
                {"root", base},
                {"candidate", actual}};
    } catch (const std::exception &error) {
        return {{"allowed", false}, {"reason", error.what()}};
    }
}
bool pathWithinRoot(const std::string &path, const std::string &root, bool missing) {
    return pathBoundaryCheck(path, root, missing).at("allowed").get<bool>();
}
Json fileIdentityMetadata(const std::string &path) {
    auto wide = utf16(path);
    Handle file(CreateFileW(wide.c_str(), FILE_READ_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (file.value == INVALID_HANDLE_VALUE)
        throw WindowsError(GetLastError(), "file identity metadata");
    return metadata(file.value);
}
HashResult hashFile(const std::string &path, std::uint64_t maxBytes, std::stop_token stop,
                    int timeoutSeconds) {
    HashResult result;
    result.status = "error";
    auto w = utf16(path);
    Handle file(CreateFileW(w.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) {
        result.error = GetLastError();
        result.status = result.error == ERROR_ACCESS_DENIED ? "permission_denied" : "file_unavailable";
        return result;
    }
    try {
        result.before = metadata(file.value);
        if ((result.before["attributes"].get<DWORD>() & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            result.status = "unsupported";
            return result;
        }
        if (result.before["size"].get<std::uint64_t>() > maxBytes) {
            result.status = "size_limit";
            return result;
        }
        CngHash hash;
        std::array<std::uint8_t, 65536> buffer{};
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSeconds);
        for (;;) {
            if (stop.stop_requested()) {
                result.status = "cancelled";
                return result;
            }
            if (std::chrono::steady_clock::now() > deadline) {
                result.status = "timeout";
                return result;
            }
            DWORD n = 0;
            if (!ReadFile(file.value, buffer.data(), buffer.size(), &n, nullptr)) {
                result.error = GetLastError();
                result.status = "read_error";
                return result;
            }
            if (!n)
                break;
            result.bytes += n;
            if (result.bytes > maxBytes) {
                result.status = "size_limit";
                return result;
            }
            hash.update(std::span(buffer.data(), n));
        }
        result.after = metadata(file.value);
        Handle current(CreateFileW(w.c_str(), FILE_READ_ATTRIBUTES,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                   OPEN_EXISTING, 0, nullptr));
        if (current.value == INVALID_HANDLE_VALUE || result.before != result.after ||
            metadata(current.value) != result.after ||
            result.bytes != result.after["size"].get<std::uint64_t>()) {
            result.status = "changed_during_scan";
            return result;
        }
        result.sha256 = hash.finish();
        result.status = "complete";
    } catch (const WindowsError &e) {
        result.error = e.code;
        result.status = "metadata_error";
    } catch (const std::exception &e) {
        result.after = {{"reason", e.what()}};
    }
    return result;
}
Json signatureFile(const std::string &path) {
    auto w = utf16(path);
    Handle h(CreateFileW(w.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING, 0, nullptr));
    if (h.value == INVALID_HANDLE_VALUE)
        return {{"status", "error"}, {"windows_error", GetLastError()}};
    unsigned char magic[2]{};
    DWORD count = 0;
    if (!ReadFile(h.value, magic, 2, &count, nullptr))
        return {{"status", "error"}, {"windows_error", GetLastError()}};
    if (count != 2 || magic[0] != 'M' || magic[1] != 'Z')
        return {{"status", "not_applicable"}, {"scope", "PE embedded Authenticode"}};
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = w.c_str();
    file.hFile = h.value;
    WINTRUST_DATA trust{};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &file;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG code = WinVerifyTrust(nullptr, &policy, &trust);
    struct TrustCloser {
        GUID &policy;
        WINTRUST_DATA &trust;
        ~TrustCloser() {
            trust.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &policy, &trust);
        }
    } cleanup{policy, trust};
    Json result = {{"status", "error"},
                   {"trust_status", static_cast<std::uint32_t>(code)},
                   {"revocation_policy", "offline_cache_only"},
                   {"scope", "PE embedded Authenticode; catalog signatures not inspected"},
                   {"signer", nullptr}};
    if (code == ERROR_SUCCESS)
        result["status"] = "valid_trusted";
    else if (code == TRUST_E_NOSIGNATURE || code == TRUST_E_SUBJECT_FORM_UNKNOWN)
        result["status"] = "unsigned";
    else if (code == CERT_E_REVOKED || code == CRYPT_E_REVOKED)
        result["status"] = "revoked";
    else if (code == CRYPT_E_REVOCATION_OFFLINE || code == CERT_E_REVOCATION_FAILURE ||
             code == CRYPT_E_NO_REVOCATION_CHECK)
        result["status"] = "unknown_revocation";
    else if (code == TRUST_E_BAD_DIGEST || code == TRUST_E_EXPLICIT_DISTRUST ||
             code == CERT_E_UNTRUSTEDROOT || code == CERT_E_EXPIRED || code == TRUST_E_SUBJECT_NOT_TRUSTED)
        result["status"] = "invalid";
    if (auto provider = WTHelperProvDataFromStateData(trust.hWVTStateData))
        if (auto signer = WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0))
            if (signer->csCertChain && signer->pasCertChain) {
                wchar_t name[1024]{};
                if (CertGetNameStringW(signer->pasCertChain[0].pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                                       nullptr, name, 1024) > 1)
                    result["signer"] = utf8(name);
            }
    return result;
}
#else
std::string sha256Bytes(std::span<const std::uint8_t>) {
    throw std::runtime_error("CNG hash requires Windows");
}
std::string expandWindowsPath(const std::string &s) { return s; }
bool pathWithinRoot(const std::string &, const std::string &, bool) { return false; }
Json pathBoundaryCheck(const std::string &, const std::string &, bool) {
    return {{"allowed", false}, {"reason", "Windows required"}};
}
Json fileIdentityMetadata(const std::string &) {
    throw std::runtime_error("file identity metadata requires Windows");
}
HashResult hashFile(const std::string &, std::uint64_t, std::stop_token, int) {
    return {"unsupported", "", 0, 0, nullptr, nullptr};
}
Json signatureFile(const std::string &) { return {{"status", "unsupported"}}; }
#endif
Json artifactMetadata(const std::string &path, std::uint64_t maxBytes, bool hash, bool signature,
                      std::stop_token stop, int timeout) {
    Json j = {{"path", path},
              {"acquired_at_utc", formatUtc(utcNow())},
              {"contents_retained", false},
              {"extension", lower(filesystemPath(path).extension().string())}};
    if (hash) {
        auto r = hashFile(path, maxBytes, stop, timeout);
        j["hash"] = {{"algorithm", "sha256"},
                     {"status", r.status},
                     {"sha256", r.sha256.empty() ? Json(nullptr) : Json(r.sha256)},
                     {"bytes", r.bytes},
                     {"error", r.error},
                     {"before", r.before},
                     {"after", r.after}};
    } else
        j["hash"] = {{"status", "disabled"}};
    j["signature"] = signature ? signatureFile(path) : Json{{"status", "disabled"}};
    if (hash && j["hash"].value("status", std::string{}) == "complete") {
        try {
            if (fileIdentityMetadata(path) != j["hash"]["after"]) {
                j["signature"] = {{"status", "changed_during_enrichment"}, {"signer", nullptr}};
                j["association"] = "file changed after hashing; signature/hash association unavailable";
            }
        } catch (const std::exception &) {
            j["association"] = "file unavailable after hashing; signature/hash association unavailable";
            j["signature"] = {{"status", "file_unavailable"}};
        }
    }
    return j;
}
} // namespace irforge
