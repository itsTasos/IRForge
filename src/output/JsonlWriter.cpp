#include "irforge/output/JsonlWriter.hpp"
#include <stdexcept>
#ifdef _WIN32
#include "irforge/monitoring/Win32.hpp"
#include <sddl.h>
#endif
namespace irforge {
JsonlWriter::JsonlWriter(const std::string &dir) : directory_(filesystemPath(dir)) {
    if (std::filesystem::is_symlink(directory_))
        throw std::runtime_error("output directory must not be a symlink");
    if (std::filesystem::exists(directory_) &&
        (!std::filesystem::is_directory(directory_) || !std::filesystem::is_empty(directory_)))
        throw std::runtime_error("output must be a new or empty private directory; choose a fresh directory "
                                 "to preserve earlier files");
    std::filesystem::create_directories(directory_);
#ifdef _WIN32
    // Protected DACL: current user as owner, SYSTEM and Administrators only.
    Handle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value))
        winCheck(GetLastError(), "OpenProcessToken for output ACL");
    DWORD size = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> data(size);
    if (!GetTokenInformation(token.value, TokenUser, data.data(), size, &size))
        winCheck(GetLastError(), "GetTokenInformation");
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(data.data())->User.Sid, &sid))
        winCheck(GetLastError(), "ConvertSidToStringSid");
    std::wstring sddl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + std::wstring(sid) + L")";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr))
        winCheck(GetLastError(), "output security descriptor");
    BOOL ok = SetFileSecurityW(directory_.c_str(),
                               DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
    DWORD error = ok ? 0 : GetLastError();
    LocalFree(sd);
    winCheck(error, "private output folder ACL");
#else
    std::filesystem::permissions(directory_, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
#endif
    for (const auto *name :
         {"events.jsonl", "alerts.jsonl", "monitor-health.json", "session-metadata.json"}) {
        if (std::filesystem::exists(directory_ / name))
            throw std::runtime_error("output contains " + std::string(name) +
                                     "; choose a fresh directory to preserve earlier logs");
    }
    events_.open(directory_ / "events.jsonl", std::ios::binary);
    alerts_.open(directory_ / "alerts.jsonl", std::ios::binary);
    if (!events_ || !alerts_)
        throw std::runtime_error("cannot open JSONL output in " + dir);
}
void JsonlWriter::event(const SecurityEvent &e) {
    std::lock_guard lock(mutex_);
    events_ << Json(e).dump() << '\n';
    if (!events_)
        throw std::runtime_error("event log write failed");
    if (++lines_ % 64 == 0)
        events_.flush();
}
void JsonlWriter::alert(const Json &j) {
    std::lock_guard lock(mutex_);
    alerts_ << j.dump() << '\n';
    alerts_.flush();
    if (!alerts_)
        throw std::runtime_error("alert log write failed");
}
void JsonlWriter::document(const std::string &name, const Json &j) {
    std::lock_guard lock(mutex_);
    auto path = directory_ / name;
    auto tmp = directory_ / (name + ".tmp");
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        f << j.dump(2) << '\n';
        f.flush();
        if (!f)
            throw std::runtime_error("document write failed: " + name);
    }
#ifdef _WIN32
    if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        winCheck(GetLastError(), "atomic health update");
#else
    std::filesystem::rename(tmp, path);
#endif
}
void JsonlWriter::flush() {
    std::lock_guard lock(mutex_);
    events_.flush();
    alerts_.flush();
    if (!events_ || !alerts_)
        throw std::runtime_error("log flush failed");
}
} // namespace irforge
