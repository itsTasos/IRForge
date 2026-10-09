#include "irforge/monitoring/FileMonitor.hpp"
#include "irforge/enrichment/HashEngine.hpp"
#include "irforge/monitoring/Win32.hpp"
#include <algorithm>
#include <cstring>
#include <map>
#include <thread>
namespace irforge {
std::vector<DirectoryNotice> decodeDirectoryNotices(const std::vector<std::uint8_t> &bytes) {
    std::vector<DirectoryNotice> result;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        if (bytes.size() - offset < 12)
            throw std::runtime_error("truncated FILE_NOTIFY_INFORMATION");
        std::uint32_t next{}, action{}, length{};
        std::memcpy(&next, bytes.data() + offset, 4);
        std::memcpy(&action, bytes.data() + offset + 4, 4);
        std::memcpy(&length, bytes.data() + offset + 8, 4);
        if (length % 2 || length > bytes.size() - offset - 12 || action < 1 || action > 5)
            throw std::runtime_error("invalid directory notice length/action");
        std::wstring name;
        name.reserve(length / 2);
        for (std::size_t i = 0; i < length; i += 2) {
            std::uint16_t c{};
            std::memcpy(&c, bytes.data() + offset + 12 + i, 2);
            name.push_back(static_cast<wchar_t>(c));
        }
        auto s = utf8(name);
        auto path = filesystemPath(s);
        bool traversal = false;
        for (const auto &component : path)
            if (component == "..")
                traversal = true;
        if (path.is_absolute() || s.empty() || s.find(':') != std::string::npos || traversal)
            throw std::runtime_error("unsafe directory notice name");
        result.push_back({action, s});
        if (!next)
            break;
        if (next < 12 + length || next % 4 || next > bytes.size() - offset)
            throw std::runtime_error("invalid directory notice offset");
        offset += next;
        if (result.size() > 4096)
            throw std::runtime_error("too many directory notices");
    }
    return result;
}
#ifdef _WIN32
struct FileMonitor::Impl {
    struct Watch {
        std::string root;
        Handle directory;
        Handle done;
        OVERLAPPED overlapped{};
        std::vector<std::uint32_t> buffer = std::vector<std::uint32_t>(16384);
        bool pending = false;
        ULONGLONG retryAt = 0;
    };
    EventBus &bus;
    Config config;
    Handle completion;
    std::vector<std::unique_ptr<Watch>> watches;
    std::jthread worker;
    std::atomic<bool> stopping = false;
    std::map<std::string, Millis> modifications;
    std::uint64_t overflows{};
    Impl(EventBus &b, Config c) : bus(b), config(std::move(c)) {}
    void gap(const std::string &reason, DWORD error) {
        SecurityEvent e;
        e.schemaVersion = 2;
        e.type = EventType::CoverageGap;
        e.timestampUtc = utcNow();
        e.source = "filesystem_diff";
        e.payload =
            ObservationPayload{{{"reason", reason}, {"windows_error", error}, {"overflows", overflows}}};
        bus.publish(std::move(e));
        monitorStatus(bus, "filesystem_diff", "degraded", reason, error, overflows);
    }
    bool arm(Watch &w) {
        w.overlapped = {};
        ResetEvent(w.done.value);
        w.overlapped.hEvent = w.done.value;
        BOOL ok = ReadDirectoryChangesW(w.directory.value, w.buffer.data(),
                                        static_cast<DWORD>(w.buffer.size() * 4), config.file_recursive,
                                        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                                            FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                                        nullptr, &w.overlapped, nullptr);
        if (!ok) {
            gap("Directory watcher cannot arm: " + w.root, GetLastError());
            return false;
        }
        w.pending = true;
        return true;
    }
    void reconcile(Watch &w) {
        Json entries = Json::array();
        std::error_code error;
        bool truncated = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        for (auto it = std::filesystem::recursive_directory_iterator(
                 filesystemPath(w.root), std::filesystem::directory_options::skip_permission_denied, error);
             it != std::filesystem::recursive_directory_iterator{} && !error; it.increment(error)) {
            if (stopping || entries.size() >= 1024 || std::chrono::steady_clock::now() >= deadline) {
                truncated = true;
                break;
            }
            if (it->is_symlink(error)) {
                it.disable_recursion_pending();
                continue;
            }
            if (it->is_regular_file(error) && pathWithinRoot(it->path().string(), w.root))
                entries.push_back(it->path().lexically_relative(filesystemPath(w.root)).string());
        }
        SecurityEvent event;
        event.schemaVersion = 2;
        event.timestampUtc = utcNow();
        event.source = "filesystem_diff";
        event.type = EventType::CoverageGap;
        event.payload = ObservationPayload{{{"reason", "bounded current-state reconciliation after overflow; "
                                                       "cannot reconstruct lost changes or actors"},
                                            {"watch_root", w.root},
                                            {"current_paths", entries},
                                            {"truncated", truncated},
                                            {"complete", !error && !truncated},
                                            {"snapshot_only", true}}};
        bus.publish(std::move(event));
    }
    void publish(Watch &w, DirectoryNotice &notice, std::optional<std::string> &previous) {
        auto u = (filesystemPath(w.root) / filesystemPath(notice.name)).u8string();
        std::string path(u.begin(), u.end());
        // Final-handle resolution rejects descendants reached through junctions
        // outside the configured root. Deletions resolve their existing parent.
        if (!pathWithinRoot(path, w.root,
                            notice.action == FILE_ACTION_REMOVED ||
                                notice.action == FILE_ACTION_RENAMED_OLD_NAME)) {
            gap("Outside-root/reparse or unavailable entry excluded", ERROR_ACCESS_DENIED);
            previous.reset();
            return;
        }
        if (notice.action == FILE_ACTION_RENAMED_OLD_NAME) {
            previous = path;
            return;
        }
        if (notice.action == FILE_ACTION_MODIFIED) {
            auto now = utcNow();
            auto found = modifications.find(path);
            if (found != modifications.end() && now - found->second < 250)
                return;
            modifications[path] = now;
            if (modifications.size() > 4096)
                modifications.erase(modifications.begin());
        }
        SecurityEvent e;
        e.schemaVersion = 2;
        e.source = "filesystem_diff";
        e.timestampUtc = utcNow();
        e.attributionMethod = "directory_notification_writer_unknown";
        e.missingData = {"file_writer"};
        e.type = notice.action == FILE_ACTION_ADDED                          ? EventType::FileCreated
                 : notice.action == FILE_ACTION_REMOVED                      ? EventType::FileDeleted
                 : notice.action == FILE_ACTION_RENAMED_NEW_NAME && previous ? EventType::FileRenamed
                                                                             : EventType::FileModified;
        e.payload = FilePayload{
            path,
            previous.value_or(""),
            eventTypeName(e.type),
            {},
            {{"watch_root", w.root}, {"rename_pair_confirmed", e.type == EventType::FileRenamed}}};
        previous.reset();
        bus.publish(std::move(e));
    }
    void loop() {
        while (!stopping) {
            for (auto &w : watches)
                if (!w->pending && GetTickCount64() >= w->retryAt) {
                    w->retryAt = GetTickCount64() + 5000;
                    if (w->directory.value == INVALID_HANDLE_VALUE || !w->directory.value) {
                        w->directory = Handle(CreateFileW(
                            utf16(w->root).c_str(), FILE_LIST_DIRECTORY,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr));
                        if (w->directory.value == INVALID_HANDLE_VALUE)
                            continue;
                        if (!CreateIoCompletionPort(w->directory.value, completion.value,
                                                    reinterpret_cast<ULONG_PTR>(w.get()), 0)) {
                            w->directory = Handle();
                            continue;
                        }
                    }
                    if (arm(*w))
                        monitorStatus(
                            bus, "filesystem_diff",
                            std::all_of(watches.begin(), watches.end(),
                                        [](const auto &watch) { return watch->pending; })
                                ? "active"
                                : "degraded",
                            "watch resumed after visible gap; lost interval cannot be reconstructed");
                    else
                        w->directory = Handle();
                }
            DWORD bytes = 0;
            ULONG_PTR key = 0;
            OVERLAPPED *overlapped = nullptr;
            BOOL ok = GetQueuedCompletionStatus(completion.value, &bytes, &key, &overlapped, 1000);
            if (!overlapped) {
                if (!ok && GetLastError() != WAIT_TIMEOUT)
                    gap("IOCP completion error", GetLastError());
                continue;
            }
            auto *watch = reinterpret_cast<Watch *>(key);
            watch->pending = false;
            if (!ok) {
                if (GetLastError() != ERROR_OPERATION_ABORTED) {
                    gap("Directory watch lost; retry scheduled", GetLastError());
                    watch->directory = Handle();
                    watch->retryAt = GetTickCount64() + 5000;
                    continue;
                }
            } else if (!bytes) {
                ++overflows;
                gap("Directory notification buffer overflow; events may be missing", ERROR_NOTIFY_ENUM_DIR);
                reconcile(*watch);
            } else
                try {
                    std::vector<std::uint8_t> copy(bytes);
                    std::memcpy(copy.data(), watch->buffer.data(), bytes);
                    auto notices = decodeDirectoryNotices(copy);
                    std::optional<std::string> rename;
                    for (auto &notice : notices)
                        publish(*watch, notice, rename);
                    if (rename) {
                        DirectoryNotice removed{
                            FILE_ACTION_REMOVED,
                            filesystemPath(*rename).lexically_relative(filesystemPath(watch->root)).string()};
                        publish(*watch, removed, rename);
                    }
                } catch (const std::exception &error) {
                    gap(error.what(), ERROR_INVALID_DATA);
                }
            if (!stopping && !arm(*watch)) {
                watch->directory = Handle();
                watch->retryAt = GetTickCount64() + 5000;
            }
        }
    }
};
FileMonitor::FileMonitor(EventBus &b, const Config &c) : impl_(std::make_unique<Impl>(b, c)) {}
FileMonitor::~FileMonitor() { stop(); }
void FileMonitor::start() {
    auto &p = *impl_;
    p.stopping = false;
    p.completion = Handle(CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1));
    if (!p.completion.value)
        throw WindowsError(GetLastError(), "CreateIoCompletionPort");
    for (auto &configured : p.config.file_roots) {
        auto watch = std::make_unique<Impl::Watch>();
        watch->root = expandWindowsPath(configured);
        watch->done = Handle(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!watch->done.value)
            throw WindowsError(GetLastError(), "watcher completion event");
        auto w = utf16(watch->root);
        watch->directory = Handle(CreateFileW(
            w.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr));
        if (watch->directory.value == INVALID_HANDLE_VALUE) {
            p.gap("Watch root unavailable: " + watch->root, GetLastError());
            watch->retryAt = GetTickCount64() + 5000;
            p.watches.push_back(std::move(watch));
            continue;
        }
        if (!CreateIoCompletionPort(watch->directory.value, p.completion.value,
                                    reinterpret_cast<ULONG_PTR>(watch.get()), 0))
            throw WindowsError(GetLastError(), "associate watch IOCP");
        if (!p.arm(*watch)) {
            watch->directory = Handle();
            watch->retryAt = GetTickCount64() + 5000;
        }
        p.watches.push_back(std::move(watch));
    }
    if (p.watches.empty())
        throw std::runtime_error("No configured directory watcher could start");
    p.worker = std::jthread([&p] { p.loop(); });
    const auto active =
        std::count_if(p.watches.begin(), p.watches.end(), [](const auto &watch) { return watch->pending; });
    monitorStatus(p.bus, "filesystem_diff",
                  active == static_cast<std::ptrdiff_t>(p.watches.size()) ? "active" : "degraded",
                  std::to_string(p.watches.size()) + " explicit roots; actor unknown; overflow observable");
}
void FileMonitor::stop() noexcept {
    if (!impl_)
        return;
    auto &p = *impl_;
    p.stopping = true;
    if (p.completion.value)
        PostQueuedCompletionStatus(p.completion.value, 0, 0, nullptr);
    if (p.worker.joinable())
        p.worker.join();
    for (auto &w : p.watches)
        if (w->pending) {
            CancelIoEx(w->directory.value, &w->overlapped);
            DWORD bytes = 0;
            GetOverlappedResult(w->directory.value, &w->overlapped, &bytes, TRUE);
            w->pending = false;
        }
    p.watches.clear();
    p.completion = Handle{};
}
#endif
} // namespace irforge
