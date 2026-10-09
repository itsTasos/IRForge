#include "irforge/storage/SqliteStore.hpp"
#include "MigrationSql.hpp"
#include "irforge/detection/IncidentGraph.hpp"
#include "irforge/enrichment/HashEngine.hpp"
#include "irforge/monitoring/Win32.hpp"
#include "irforge/remote/RemoteProtocol.hpp"
#include <limits>
#include <set>
#include <sqlite3.h>
namespace irforge {
namespace {
void check(sqlite3 *db, int code) {
    if (code != SQLITE_OK && code != SQLITE_DONE && code != SQLITE_ROW)
        throw std::runtime_error("SQLite " + std::to_string(code) + ": " + sqlite3_errmsg(db));
}
struct Statement {
    sqlite3 *db;
    sqlite3_stmt *p{};
    Statement(sqlite3 *d, const std::string &sql) : db(d) {
        check(db, sqlite3_prepare_v2(db, sql.c_str(), -1, &p, nullptr));
    }
    ~Statement() { sqlite3_finalize(p); }
    Statement &bind(int n, const std::string &s) {
        check(db, sqlite3_bind_text(p, n, s.c_str(), static_cast<int>(s.size()), SQLITE_TRANSIENT));
        return *this;
    }
    Statement &bind(int n, std::int64_t v) {
        check(db, sqlite3_bind_int64(p, n, v));
        return *this;
    }
    Statement &null(int n) {
        check(db, sqlite3_bind_null(p, n));
        return *this;
    }
    bool step() {
        int c = sqlite3_step(p);
        check(db, c);
        return c == SQLITE_ROW;
    }
    std::string text(int n) {
        auto s = sqlite3_column_text(p, n);
        return s ? reinterpret_cast<const char *>(s) : "";
    }
    std::int64_t number(int n) { return sqlite3_column_int64(p, n); }
};
void exec(sqlite3 *db, const char *sql) {
    char *error = nullptr;
    int c = sqlite3_exec(db, sql, nullptr, nullptr, &error);
    std::string reason = error ? error : "";
    sqlite3_free(error);
    if (c != SQLITE_OK)
        throw std::runtime_error("SQLite migration/transaction: " + reason);
}
struct Transaction {
    sqlite3 *db;
    bool committed = false;
    explicit Transaction(sqlite3 *d) : db(d) { exec(db, "BEGIN IMMEDIATE"); }
    ~Transaction() {
        if (!committed)
            sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
    }
    void commit() {
        exec(db, "COMMIT");
        committed = true;
    }
};
const std::set<std::string> kvTables = {"baselines", "health", "log_bookmarks", "ti_cache", "settings"};
std::string scopedIncident(const Json &j) {
    return j.at("host_id").get<std::string>() + "/" + j.at("session_id").get<std::string>() + "/" +
           j.at("incident_id").get<std::string>();
}
} // namespace
struct SqliteStore::Impl {
    sqlite3 *db{};
    Handle ownership;
    std::uint64_t maxBytes;
    std::thread::id owner = std::this_thread::get_id();
    ~Impl() {
        if (db)
            sqlite3_close_v2(db);
    }
    void own() {
        if (owner != std::this_thread::get_id())
            throw std::runtime_error("SQLite writer accessed from wrong thread");
    }
};
SqliteStore::SqliteStore(const std::string &path, std::uint64_t maxBytes) : impl_(std::make_unique<Impl>()) {
    if (maxBytes < 1024 * 1024 || maxBytes > 16ULL * 1024 * 1024 * 1024)
        throw std::runtime_error("DB quota must be 1 MiB..16 GiB");
    impl_->maxBytes = maxBytes;
    auto p = filesystemPath(path);
    auto canonical = lower(std::filesystem::absolute(p).lexically_normal().string());
    auto digest =
        sha256Bytes(std::span(reinterpret_cast<const std::uint8_t *>(canonical.data()), canonical.size()));
    impl_->ownership = Handle(CreateMutexW(nullptr, FALSE, utf16("Local\\IRForge.DB." + digest).c_str()));
    if (!impl_->ownership.value || GetLastError() == ERROR_ALREADY_EXISTS)
        throw std::runtime_error("database already owned by an IRForge agent; use authenticated IPC or stop "
                                 "its owner before offline commands");
    if (p.has_parent_path())
        std::filesystem::create_directories(p.parent_path());
    int c = sqlite3_open_v2(path.c_str(), &impl_->db,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, nullptr);
    check(impl_->db, c);
    auto db = impl_->db;
    sqlite3_extended_result_codes(db, 1);
    sqlite3_busy_timeout(db, 5000);
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 4 * 1024 * 1024);
    sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 1024 * 1024);
    sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr);
    exec(db, "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA "
             "trusted_schema=OFF; PRAGMA wal_autocheckpoint=256; PRAGMA journal_size_limit=67108864;");
    Statement version(db, "PRAGMA user_version");
    version.step();
    auto v = version.number(0);
    if (v > 2)
        throw std::runtime_error("DB schema is newer than this build");
    if (v < 2) {
        Transaction t(db);
        if (v < 1)
            exec(db, migration_sql::initial);
        if (v < 2)
            exec(db, migration_sql::aliases);
        Statement h(db, "INSERT INTO migration_history(version,applied_ms) VALUES(?,?)");
        h.bind(1, 2).bind(2, utcNow()).step();
        exec(db, "PRAGMA user_version=2");
        t.commit();
    }
    Statement quota(db, "PRAGMA max_page_count=" + std::to_string(maxBytes / 4096));
    quota.step();
    Statement integrity(db, "PRAGMA quick_check");
    if (!integrity.step() || integrity.text(0) != "ok")
        throw std::runtime_error("SQLite quick_check failed; preserve DB and recover from a verified backup");
}
SqliteStore::~SqliteStore() = default;
void SqliteStore::session(const std::string &host, const std::string &id, const Json &j) {
    impl_->own();
    validateDocument(j);
    auto db = impl_->db;
    Transaction t(db);
    Statement owner(db, "SELECT host_id FROM sessions WHERE id=?");
    owner.bind(1, id);
    if (owner.step() && owner.text(0) != host)
        throw std::runtime_error("session already belongs to another host");
    Statement h(db, "INSERT INTO hosts(id,name,document) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET "
                    "name=excluded.name,document=excluded.document");
    h.bind(1, host)
        .bind(2, j.value("host", host))
        .bind(3, Json{{"host_id", host}, {"name", j.value("host", host)}}.dump())
        .step();
    Statement s(db, "INSERT INTO sessions(id,host_id,mode,started_ms,document) VALUES(?,?,?,?,?) ON "
                    "CONFLICT(id) DO UPDATE SET document=excluded.document");
    s.bind(1, id)
        .bind(2, host)
        .bind(3, j.value("mode", std::string("unknown")))
        .bind(4, j.contains("start_utc") ? parseUtc(j.at("start_utc").get<std::string>()) : utcNow())
        .bind(5, j.dump())
        .step();
    t.commit();
}
std::string SqliteStore::event(const Json &j) {
    impl_->own();
    validateDocument(j);
    auto e = j.get<SecurityEvent>();
    if (e.schemaVersion != 2)
        throw std::runtime_error("store requires upgraded v2 event");
    auto db = impl_->db;
    auto key = observationDedupKey(e);
    std::string canonical = e.uniqueId;
    Transaction t(db);
    Statement old(db, "SELECT id,document FROM events WHERE dedup_key=?");
    old.bind(1, key);
    bool duplicate = old.step();
    Json merged = j;
    if (duplicate) {
        canonical = old.text(0);
        merged = Json::parse(old.text(1));
        auto &target = merged["payload"];
        for (auto it = j.at("payload").begin(); it != j.at("payload").end(); ++it)
            if (!target.contains(it.key()) || target[it.key()].is_null())
                target[it.key()] = it.value();
        if (j["payload"].contains("identity") && j["payload"]["identity"].contains("sysmon_process_guid"))
            target["identity"]["sysmon_process_guid"] = j["payload"]["identity"]["sysmon_process_guid"];
        Statement update(db, "UPDATE events SET document=? WHERE id=?");
        update.bind(1, merged.dump()).bind(2, canonical).step();
    } else {
        Statement s(db, "INSERT INTO "
                        "events(id,host_id,session_id,sequence,event_type,source,timestamp_ms,actor_pid,"
                        "related_pid,dedup_key,document) VALUES(?,?,?,?,?,?,?,?,?,?,?)");
        if (e.id > static_cast<std::uint64_t>(INT64_MAX))
            throw std::runtime_error("event sequence exceeds SQLite signed integer range");
        s.bind(1, canonical)
            .bind(2, e.hostId)
            .bind(3, e.sessionId)
            .bind(4, static_cast<std::int64_t>(e.id))
            .bind(5, eventTypeName(e.type))
            .bind(6, e.source)
            .bind(7, e.timestampUtc);
        std::optional<ProcessId> actor, related;
        if (auto p = std::get_if<ProcessPayload>(&e.payload))
            related = p->identity.pid;
        if (auto n = std::get_if<TcpPayload>(&e.payload))
            related = n->ownerPid;
        if (auto r = std::get_if<RegistryPayload>(&e.payload))
            actor = r->actorPid;
        if (auto f = std::get_if<FilePayload>(&e.payload))
            actor = f->actorPid;
        if (actor)
            s.bind(8, *actor);
        else
            s.null(8);
        if (related)
            s.bind(9, *related);
        else
            s.null(9);
        s.bind(10, key).bind(11, j.dump()).step();
    }
    Statement provenance(
        db,
        "INSERT OR IGNORE INTO event_provenance(event_id,source,source_record_id,document) VALUES(?,?,?,?)");
    provenance.bind(1, canonical)
        .bind(2, e.source)
        .bind(3, e.sourceRecordId.empty() ? e.uniqueId : e.sourceRecordId)
        .bind(4, j.dump())
        .step();
    Statement alias(db, "INSERT OR IGNORE INTO event_aliases(id,canonical_id) VALUES(?,?)");
    alias.bind(1, e.uniqueId).bind(2, canonical).step();
    if (auto p = std::get_if<ProcessPayload>(&e.payload)) {
        Statement s(db, "INSERT INTO processes(id,host_id,pid,created_ms,document) VALUES(?,?,?,?,?) ON "
                        "CONFLICT(id) DO UPDATE SET document=excluded.document");
        s.bind(1, e.hostId + "/" + identityKey(p->identity))
            .bind(2, e.hostId)
            .bind(3, p->identity.pid)
            .bind(4, e.timestampUtc)
            .bind(5, merged.dump())
            .step();
    }
    if (auto f = std::get_if<FilePayload>(&e.payload); f && e.type == EventType::ArtifactEnriched) {
        Statement s(db,
                    "INSERT INTO artifacts(id,host_id,path,updated_ms,document) VALUES(?,?,?,?,?) ON "
                    "CONFLICT(id) DO UPDATE SET updated_ms=excluded.updated_ms,document=excluded.document");
        s.bind(1, e.hostId + "/" + normalizePath(f->path))
            .bind(2, e.hostId)
            .bind(3, f->path)
            .bind(4, e.timestampUtc)
            .bind(5, j.dump())
            .step();
    }
    if (!e.bookmarkXml.empty() && !e.providerChannel.empty())
        put("log_bookmarks", e.providerChannel,
            {{"xml", e.bookmarkXml}, {"event_id", canonical}, {"source_record_id", e.sourceRecordId}});
    spool({{"kind", "event"}, {"host_id", e.hostId}, {"session_id", e.sessionId}, {"data", j}});
    t.commit();
    return canonical;
}
void SqliteStore::incident(Json j) {
    impl_->own();
    validateDocument(j);
    auto db = impl_->db;
    std::string id = scopedIncident(j);
    j["local_incident_id"] = j["incident_id"];
    j["incident_id"] = id;
    Transaction t(db);
    Statement old(db, "SELECT status,revision FROM incidents WHERE id=?");
    old.bind(1, id);
    int revision = 1;
    if (old.step()) {
        j["status"] = old.text(0);
        revision = static_cast<int>(old.number(1)) + 1;
    }
    j["revision"] = revision;
    Statement s(
        db, "INSERT INTO incidents(id,host_id,session_id,status,severity,score,updated_ms,revision,document) "
            "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "severity=excluded.severity,score=excluded.score,updated_ms=excluded.updated_ms,revision="
            "excluded.revision,document=excluded.document");
    s.bind(1, id)
        .bind(2, j.at("host_id").get<std::string>())
        .bind(3, j.at("session_id").get<std::string>())
        .bind(4, j.value("status", std::string("new")))
        .bind(5, j.at("severity").get<std::string>())
        .bind(6, j.at("score").get<int>())
        .bind(7, parseUtc(j.at("last_updated_at").get<std::string>()))
        .bind(8, revision)
        .bind(9, j.dump())
        .step();
    for (auto &ev : j.at("event_ids")) {
        auto alias = j.at("host_id").get<std::string>() + "/" + j.at("session_id").get<std::string>() + "/" +
                     std::to_string(ev.get<EventId>());
        Statement link(db, "INSERT OR IGNORE INTO incident_events(incident_id,event_id) SELECT "
                           "?,canonical_id FROM event_aliases WHERE id=?");
        link.bind(1, id).bind(2, alias).step();
    }
    for (auto &m : j.at("matched_rules")) {
        Statement rule(db, "INSERT INTO rule_matches(id,incident_id,document) VALUES(?,?,?) ON CONFLICT(id) "
                           "DO UPDATE SET document=excluded.document");
        rule.bind(1, id + "/" + m.at("rule_id").get<std::string>()).bind(2, id).bind(3, m.dump()).step();
    }
    spool({{"kind", "incident"},
           {"host_id", j.at("host_id")},
           {"session_id", j.at("session_id")},
           {"data", j}});
    t.commit();
}
Json SqliteStore::query(const std::string &table, const Json &filters, int limit, int offset) {
    impl_->own();
    validateDocument(filters);
    if (limit < 1 || limit > 500 || offset < 0 || offset > 10000000)
        throw std::runtime_error("invalid pagination");
    static const std::set<std::string> allowed = {"events", "incidents", "processes",    "artifacts",
                                                  "hosts",  "sessions",  "config_audit", "analyst_notes",
                                                  "cases",  "ti_cache",  "health",       "baselines"};
    if (!allowed.contains(table))
        throw std::runtime_error("unsupported query table");
    std::string where = " WHERE 1=1";
    std::vector<std::string> values;
    const std::map<std::string, std::string> columns = {
        {"host", "host_id"},      {"type", "event_type"}, {"source", "source"},     {"pid", "related_pid"},
        {"severity", "severity"}, {"status", "status"},   {"session", "session_id"}};
    for (auto it = filters.begin(); it != filters.end(); ++it) {
        if (it.key() == "types") {
            if (table != "events" || !it.value().is_array() || it.value().empty() || it.value().size() > 32)
                throw std::runtime_error("event type list bounds");
            where += " AND event_type IN (";
            for (const auto &type : it.value()) {
                auto name = type.get<std::string>();
                (void)parseEventType(name);
                if (where.back() != '(')
                    where += ',';
                where += '?';
                values.push_back(name);
            }
            where += ')';
            continue;
        }
        if (it.key() == "from" || it.key() == "to") {
            if (table != "events")
                throw std::runtime_error("time filters currently apply to events");
            where += it.key() == "from" ? " AND timestamp_ms>=?" : " AND timestamp_ms<=?";
            values.push_back(std::to_string(parseUtc(it.value().get<std::string>())));
            continue;
        }
        if (it.key() == "search") {
            where += " AND instr(lower(document),lower(?))>0";
            values.push_back(it.value().get<std::string>());
            continue;
        }
        if (it.key() == "id" && table == "cases") {
            where += " AND id=?";
            values.push_back(it.value().get<std::string>());
            continue;
        }
        auto c = columns.find(it.key());
        if (c == columns.end())
            throw std::runtime_error("unsupported filter");
        bool valid =
            (table == "events" && (it.key() == "host" || it.key() == "type" || it.key() == "source" ||
                                   it.key() == "pid" || it.key() == "session")) ||
            (table == "incidents" && (it.key() == "host" || it.key() == "status" || it.key() == "severity" ||
                                      it.key() == "session")) ||
            ((table == "artifacts" || table == "processes" || table == "sessions" || table == "hosts") &&
             it.key() == "host");
        if (!valid)
            throw std::runtime_error("filter incompatible with table");
        where += " AND " + (table == "hosts" && it.key() == "host" ? "id" : c->second) + "=?";
        values.push_back(it.value().is_string() ? it.value().get<std::string>() : it.value().dump());
    }
    Statement count(impl_->db, "SELECT count(*) FROM " + table + where);
    int n = 1;
    for (auto &v : values)
        count.bind(n++, v);
    count.step();
    auto total = count.number(0);
    std::string order = table == "events"                              ? "timestamp_ms DESC,id"
                        : table == "incidents" || table == "artifacts" ? "updated_ms DESC,id"
                                                                       : "id";
    Statement rows(impl_->db,
                   "SELECT document FROM " + table + where + " ORDER BY " + order + " LIMIT ? OFFSET ?");
    n = 1;
    for (auto &v : values)
        rows.bind(n++, v);
    rows.bind(n, limit);
    rows.bind(n + 1, offset);
    Json result = Json::array();
    while (rows.step()) {
        auto document = Json::parse(rows.text(0));
        if ((table == "events" || table == "incidents") && document.contains("session_id")) {
            Statement mode(impl_->db, "SELECT mode FROM sessions WHERE id=?");
            mode.bind(1, document.at("session_id").get<std::string>());
            if (mode.step())
                document["acquisition_mode"] = mode.text(0);
        }
        if (table == "hosts") {
            auto remote = get("health", "remote/" + document.at("host_id").get<std::string>());
            if (!remote.is_null())
                document["remote_health"] = remote;
            Statement mode(impl_->db,
                           "SELECT mode FROM sessions WHERE host_id=? ORDER BY started_ms DESC LIMIT 1");
            mode.bind(1, document.at("host_id").get<std::string>());
            if (mode.step())
                document["mode"] = mode.text(0);
        }
        result.push_back(std::move(document));
    }
    return {{"rows", result},
            {"total", total},
            {"offset", offset},
            {"limit", limit},
            {"has_more", offset + result.size() < static_cast<std::size_t>(total)}};
}
Json SqliteStore::detail(const std::string &id) {
    impl_->own();
    Statement s(impl_->db, "SELECT document,revision FROM incidents WHERE id=?");
    s.bind(1, id);
    if (!s.step())
        throw std::runtime_error("incident not found");
    auto j = Json::parse(s.text(0));
    Statement sourceMode(impl_->db, "SELECT mode,document FROM sessions WHERE id=?");
    sourceMode.bind(1, j.at("session_id").get<std::string>());
    if (sourceMode.step()) {
        j["acquisition_mode"] = sourceMode.text(0);
        j["acquisition_context"] = Json::parse(sourceMode.text(1));
    }
    j["revision"] = s.number(1);
    j["timeline"] = Json::array();
    Statement e(impl_->db, "SELECT e.document FROM events e JOIN incident_events i ON e.id=i.event_id WHERE "
                           "i.incident_id=? ORDER BY e.timestamp_ms,e.id");
    e.bind(1, id);
    while (e.step())
        j["timeline"].push_back(Json::parse(e.text(0)));
    j["coverage_gaps"] = Json::array();
    Statement gaps(impl_->db, "SELECT document FROM events WHERE host_id=? AND (event_type='coverage_gap' OR "
                              "(event_type='monitor_status' AND json_extract(document,'$.payload.state') IN "
                              "('degraded','disabled','failed','error'))) "
                              "AND timestamp_ms>=? AND timestamp_ms<=? ORDER BY timestamp_ms LIMIT 128");
    gaps.bind(1, j.at("host_id").get<std::string>())
        .bind(2, parseUtc(j.at("opened_at").get<std::string>()) - 60000)
        .bind(3, parseUtc(j.at("last_updated_at").get<std::string>()) + 60000);
    while (gaps.step())
        j["coverage_gaps"].push_back(Json::parse(gaps.text(0)));
    auto graph = incidentGraph(j["timeline"]);
    j["graph"] = graph;
    j["relationships"] = graph["edges"];
    j["analyst_annotations"] = Json::array();
    Statement a(impl_->db, "SELECT document FROM analyst_notes WHERE incident_id=? ORDER BY id");
    a.bind(1, id);
    while (a.step())
        j["analyst_annotations"].push_back(Json::parse(a.text(0)));
    return j;
}
Json SqliteStore::createCase(const std::string &title, const std::vector<std::string> &ids,
                             const std::string &author) {
    impl_->own();
    if (title.empty() || title.size() > 256 || ids.empty() || ids.size() > 128 ||
        std::set<std::string>(ids.begin(), ids.end()).size() != ids.size())
        throw std::runtime_error("case title/incident count/duplicates invalid");
    Json details = Json::array();
    Json snapshots = Json::array();
    std::string host;
    for (const auto &id : ids) {
        auto incident = detail(id);
        if (host.empty())
            host = incident.at("host_id").get<std::string>();
        if (incident.at("host_id") != host)
            throw std::runtime_error("local case cannot mix hosts");
        details.push_back({{"incident_id", id}, {"revision", incident["revision"]}});
        snapshots.push_back(incident);
    }
    auto id = newUuid();
    Json document = {{"case_id", id},
                     {"title", title},
                     {"host_id", host},
                     {"incident_ids", ids},
                     {"incident_revisions", details},
                     {"incident_snapshots", snapshots},
                     {"created_at", formatUtc(utcNow())},
                     {"author", author},
                     {"revision", 1},
                     {"summary", "Operator-selected immutable acquisition references"}};
    validateDocument(document, 4 * 1048576);
    Transaction transaction(impl_->db);
    Statement insert(impl_->db, "INSERT INTO cases(id,created_ms,document) VALUES(?,?,?)");
    insert.bind(1, id).bind(2, utcNow()).bind(3, document.dump()).step();
    audit(author, {{"operation", "case_create"}, {"case_id", id}, {"incident_ids", ids}});
    transaction.commit();
    return document;
}
void SqliteStore::annotate(const std::string &id, const std::string &author, const std::string &text,
                           const std::string &state) {
    impl_->own();
    if (text.size() > 8192 || author.empty() || author.size() > 512 ||
        !std::set<std::string>{"new", "investigating", "benign", "resolved"}.contains(state))
        throw std::runtime_error("invalid annotation/state");
    auto j = detail(id);
    Json note = {{"author", author},
                 {"text", text},
                 {"status", state},
                 {"timestamp_utc", formatUtc(utcNow())},
                 {"incident_revision", j["revision"]}};
    Transaction t(impl_->db);
    Statement n(impl_->db,
                "INSERT INTO analyst_notes(incident_id,author,created_ms,document) VALUES(?,?,?,?)");
    n.bind(1, id).bind(2, author).bind(3, utcNow()).bind(4, note.dump()).step();
    j["status"] = state;
    Statement update(impl_->db, "UPDATE incidents SET status=?,revision=revision+1,document=? WHERE id=?");
    update.bind(1, state).bind(2, j.dump()).bind(3, id).step();
    Statement auditRow(impl_->db, "INSERT INTO config_audit(author,created_ms,document) VALUES(?,?,?)");
    auditRow.bind(1, author)
        .bind(2, utcNow())
        .bind(3, Json{{"operation", "incident_annotation"}, {"incident_id", id}, {"note", note}}.dump())
        .step();
    t.commit();
}
Json SqliteStore::get(const std::string &table, const std::string &key) {
    impl_->own();
    if (!kvTables.contains(table))
        throw std::runtime_error("unsupported state table");
    Statement s(impl_->db, "SELECT document FROM " + table + " WHERE id=?");
    s.bind(1, key);
    return s.step() ? Json::parse(s.text(0)) : Json(nullptr);
}
void SqliteStore::put(const std::string &table, const std::string &key, const Json &j, Millis expires) {
    impl_->own();
    if (!kvTables.contains(table) || key.empty() || key.size() > 512)
        throw std::runtime_error("invalid state key/table");
    validateDocument(j);
    std::string sql =
        table == "ti_cache"
            ? "INSERT INTO ti_cache(id,updated_ms,expires_ms,document) VALUES(?,?,?,?) ON CONFLICT(id) DO "
              "UPDATE SET "
              "updated_ms=excluded.updated_ms,expires_ms=excluded.expires_ms,document=excluded.document"
            : "INSERT INTO " + table +
                  "(id,updated_ms,document) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET "
                  "updated_ms=excluded.updated_ms,document=excluded.document";
    Statement s(impl_->db, sql);
    s.bind(1, key).bind(2, utcNow());
    if (table == "ti_cache")
        s.bind(3, expires).bind(4, j.dump());
    else
        s.bind(3, j.dump());
    s.step();
}
void SqliteStore::audit(const std::string &author, const Json &j) {
    impl_->own();
    validateDocument(j);
    Statement s(impl_->db, "INSERT INTO config_audit(author,created_ms,document) VALUES(?,?,?)");
    s.bind(1, author).bind(2, utcNow()).bind(3, j.dump()).step();
}
Json SqliteStore::health() {
    impl_->own();
    Json j = {{"schema_version", 2}, {"backend", "sqlite"}, {"quota_bytes", impl_->maxBytes}};
    for (auto table : {"events", "incidents", "processes", "artifacts", "remote_spool"}) {
        Statement s(impl_->db, std::string("SELECT count(*) FROM ") + table);
        s.step();
        j[table] = s.number(0);
    }
    Statement bytes(impl_->db, "SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size()");
    bytes.step();
    j["database_bytes"] = bytes.number(0);
    j["threat_intelligence_quota"] = get("settings", "ti/virustotal-budget");
    j["remote_transport"] = get("health", "remote_transport");
    std::error_code diskError;
    auto filename = filesystemPath(sqlite3_db_filename(impl_->db, "main"));
    auto wal = filename;
    wal += "-wal";
    auto walBytes = std::filesystem::file_size(wal, diskError);
    j["wal_bytes"] = diskError ? 0 : walBytes;
    j["severity_counts"] = Json::object();
    Statement severity(impl_->db, "SELECT severity,count(*) FROM incidents GROUP BY severity");
    while (severity.step())
        j["severity_counts"][severity.text(0)] = severity.number(1);
    j["events_by_utc_hour"] = Json::array();
    Statement hourly(impl_->db,
                     "SELECT strftime('%Y-%m-%dT%H:00:00Z',timestamp_ms/1000,'unixepoch'),count(*) FROM "
                     "events GROUP BY 1 ORDER BY 1 DESC LIMIT 48");
    while (hourly.step())
        j["events_by_utc_hour"].push_back({{"hour", hourly.text(0)}, {"count", hourly.number(1)}});
    return j;
}
Json SqliteStore::retention(Millis now, int eventDays, int incidentDays, int spoolDays) {
    impl_->own();
    if (eventDays < 1 || incidentDays < eventDays || spoolDays < 1)
        throw std::runtime_error("invalid retention");
    Transaction t(impl_->db);
    auto db = impl_->db;
    Statement i(db, "DELETE FROM incidents WHERE updated_ms<? AND status IN ('benign','resolved')");
    i.bind(1, now - incidentDays * 86400000LL).step();
    auto incidents = sqlite3_changes(db);
    Statement e(
        db, "DELETE FROM events WHERE timestamp_ms<? AND id NOT IN(SELECT event_id FROM incident_events)");
    e.bind(1, now - eventDays * 86400000LL).step();
    auto events = sqlite3_changes(db);
    Statement processes(
        db, "DELETE FROM processes AS p WHERE created_ms<? AND NOT EXISTS (SELECT 1 FROM events e WHERE "
            "e.host_id=p.host_id AND "
            "json_extract(e.document,'$.payload.identity')=json_extract(p.document,'$.payload.identity'))");
    processes.bind(1, now - eventDays * 86400000LL).step();
    Statement artifacts(
        db, "DELETE FROM artifacts WHERE updated_ms<? AND document NOT IN(SELECT document FROM events)");
    artifacts.bind(1, now - eventDays * 86400000LL).step();
    Statement s(db, "DELETE FROM remote_spool WHERE created_ms<?");
    s.bind(1, now - spoolDays * 86400000LL).step();
    auto spool = sqlite3_changes(db);
    Statement ti(db, "DELETE FROM ti_cache WHERE expires_ms<?");
    ti.bind(1, now).step();
    t.commit();
    return {{"events_removed", events}, {"incidents_removed", incidents}, {"spool_expired_loss", spool}};
}
void SqliteStore::checkpoint() {
    impl_->own();
    check(impl_->db,
          sqlite3_wal_checkpoint_v2(impl_->db, nullptr, SQLITE_CHECKPOINT_PASSIVE, nullptr, nullptr));
}
void SqliteStore::spool(const Json &input) {
    impl_->own();
    exec(impl_->db, "SAVEPOINT optional_remote_spool");
    try {
        auto configuration = get("settings", "remote/config");
        if (configuration.is_null() || !configuration.value("enabled", false)) {
            exec(impl_->db, "RELEASE optional_remote_spool");
            return;
        }
        Json packet = input;
        auto agent = configuration.at("agent_id").get<std::string>(),
             session = packet.at("session_id").get<std::string>();
        if (agent.empty() || agent.size() > 128 || session.size() > 128)
            throw std::runtime_error("spool identity bound");
        auto sequenceKey = "remote/sequence/" + session;
        auto state = get("settings", sequenceKey);
        auto sequence = state.is_null() ? 1 : state.at("last").get<std::uint64_t>() + 1;
        if (sequence > static_cast<std::uint64_t>(INT64_MAX))
            throw std::runtime_error("spool sequence exhausted");
        packet["schema_version"] = 1;
        packet["agent_id"] = agent;
        packet["sequence"] = sequence;
        if (packet["kind"] == "event")
            packet["data"] =
                redactRemoteEvent(packet["data"], configuration.value("redact_command_lines", true));
        auto wire = packet.dump();
        if (wire.size() > 1048000)
            throw std::runtime_error("remote metadata packet exceeds 1 MiB");
        Statement row(
            impl_->db,
            "INSERT INTO remote_spool(agent_id,session_id,sequence,created_ms,document) VALUES(?,?,?,?,?)");
        row.bind(1, agent)
            .bind(2, session)
            .bind(3, static_cast<std::int64_t>(sequence))
            .bind(4, utcNow())
            .bind(5, wire)
            .step();
        put("settings", sequenceKey, {{"last", sequence}});
        auto maxItems = configuration.value("max_items", 10000);
        auto maxBytes = configuration.value("max_bytes", 128ULL * 1048576);
        if (maxItems < 100 || maxItems > 100000 || maxBytes < 1048576 || maxBytes > 1024ULL * 1048576)
            throw std::runtime_error("spool quota outside supported bounds");
        std::uint64_t lost = 0;
        for (;;) {
            Statement size(impl_->db, "SELECT count(*),coalesce(sum(length(document)),0) FROM remote_spool");
            size.step();
            if (size.number(0) <= maxItems && static_cast<std::uint64_t>(size.number(1)) <= maxBytes)
                break;
            exec(impl_->db, "DELETE FROM remote_spool WHERE id=(SELECT min(id) FROM remote_spool)");
            ++lost;
        }
        if (lost) {
            auto prior = get("health", "remote_spool_loss");
            put("health", "remote_spool_loss",
                {{"dropped", lost + (prior.is_null() ? 0 : prior.value("dropped", std::uint64_t{}))},
                 {"reason", "durable offline spool quota"}});
        }
        exec(impl_->db, "RELEASE optional_remote_spool");
    } catch (const std::exception &error) {
        // Optional delivery cannot veto the local evidence transaction.
        exec(impl_->db, "ROLLBACK TO optional_remote_spool");
        exec(impl_->db, "RELEASE optional_remote_spool");
        try {
            auto prior = get("health", "remote_spool_loss");
            put("health", "remote_spool_loss",
                {{"dropped", 1 + (prior.is_null() ? 0 : prior.value("dropped", std::uint64_t{}))},
                 {"reason", error.what()}});
        } catch (...) {
        }
    }
}
Json SqliteStore::spoolNext(int limit) {
    impl_->own();
    if (limit < 1 || limit > 100)
        throw std::runtime_error("spool page bound");
    Statement first(impl_->db, "SELECT agent_id,session_id FROM remote_spool ORDER BY id LIMIT 1");
    if (!first.step())
        return {{"schema_version", 1}, {"packets", Json::array()}};
    Statement rows(
        impl_->db,
        "SELECT document FROM remote_spool WHERE agent_id=? AND session_id=? ORDER BY sequence LIMIT ?");
    rows.bind(1, first.text(0)).bind(2, first.text(1)).bind(3, limit);
    Json packets = Json::array();
    std::size_t bytes = 128;
    while (rows.step()) {
        auto text = rows.text(0);
        if (bytes + text.size() > 1048576)
            break;
        bytes += text.size() + 1;
        packets.push_back(Json::parse(text));
    }
    return {{"schema_version", 1}, {"packets", packets}};
}
void SqliteStore::spoolAck(const std::string &agent, const std::string &session, std::uint64_t sequence) {
    impl_->own();
    auto configuration = get("settings", "remote/config");
    auto last = get("settings", "remote/sequence/" + session);
    if (configuration.is_null() || configuration.at("agent_id") != agent || last.is_null() ||
        sequence > last.at("last").get<std::uint64_t>() || sequence > static_cast<std::uint64_t>(INT64_MAX))
        throw std::runtime_error("ACK exceeds agent/session durable sequence");
    Transaction transaction(impl_->db);
    Statement remove(impl_->db, "DELETE FROM remote_spool WHERE agent_id=? AND session_id=? AND sequence<=?");
    remove.bind(1, agent).bind(2, session).bind(3, static_cast<std::int64_t>(sequence)).step();
    put("settings", "remote/ack/" + session,
        {{"agent_id", agent}, {"sequence", sequence}, {"acknowledged_at", formatUtc(utcNow())}});
    transaction.commit();
}
Json SqliteStore::request(const Json &r) {
    if (r.at("op") == "baseline_flush") {
        Transaction t(impl_->db);
        auto key = r.at("key").get<std::string>();
        auto old = get("baselines", key);
        if (!old.is_null() && old.value("control_revision", std::string{}) !=
                                  r.at("expected_control_revision").get<std::string>()) {
            t.commit();
            return old;
        }
        put("baselines", key, r.at("data"));
        t.commit();
        return r.at("data");
    }
    if (r.at("op") == "spool_next")
        return spoolNext(r.value("limit", 100));
    if (r.at("op") == "spool_ack") {
        spoolAck(r.at("agent_id"), r.at("session_id"), r.at("sequence").get<std::uint64_t>());
        return {{"ok", true}};
    }
    if (r.at("op") == "ti_reserve") {
        impl_->own();
        Transaction transaction(impl_->db);
        auto now = r.at("now").get<Millis>();
        auto budget = get("settings", "ti/virustotal-budget");
        if (budget.is_null())
            budget = {{"minute_start", now},
                      {"minute_count", 0},
                      {"day", now / 86400000},
                      {"day_count", 0},
                      {"retry_at", 0}};
        if (now - budget.at("minute_start").get<Millis>() >= 60000) {
            budget["minute_start"] = now;
            budget["minute_count"] = 0;
        }
        if (budget["day"] != now / 86400000) {
            budget["day"] = now / 86400000;
            budget["day_count"] = 0;
        }
        bool allowed = budget["minute_count"].get<int>() < 4 && budget["day_count"].get<int>() < 500 &&
                       budget["retry_at"].get<Millis>() <= now;
        Millis retry = budget["retry_at"].get<Millis>();
        if (budget["minute_count"].get<int>() >= 4)
            retry = std::max(retry, budget["minute_start"].get<Millis>() + 60000);
        if (budget["day_count"].get<int>() >= 500)
            retry = std::max(retry, (now / 86400000 + 1) * 86400000);
        if (allowed) {
            budget["minute_count"] = budget["minute_count"].get<int>() + 1;
            budget["day_count"] = budget["day_count"].get<int>() + 1;
        }
        put("settings", "ti/virustotal-budget", budget);
        transaction.commit();
        return {{"allowed", allowed}, {"retry_at", formatUtc(retry)}, {"budget", budget}};
    }
    if (r.at("op") == "ti_backoff") {
        impl_->own();
        Transaction transaction(impl_->db);
        auto budget = get("settings", "ti/virustotal-budget");
        if (budget.is_null())
            throw std::runtime_error("TI budget missing");
        budget["retry_at"] = std::max(budget.value("retry_at", Millis{}), r.at("retry_at").get<Millis>());
        put("settings", "ti/virustotal-budget", budget);
        transaction.commit();
        return {{"ok", true}};
    }
    if (r.at("op") == "case_create")
        return createCase(r.at("title"), r.at("incident_ids").get<std::vector<std::string>>(),
                          r.at("author"));
    validateDocument(r);
    auto op = r.at("op").get<std::string>();
    if (op == "session") {
        session(r.at("host"), r.at("id"), r.at("data"));
        return {{"ok", true}};
    }
    if (op == "event")
        return {{"canonical_id", event(r.at("data"))}};
    if (op == "incident") {
        incident(r.at("data"));
        return {{"ok", true}};
    }
    if (op == "query")
        return query(r.at("table"), r.value("filters", Json::object()), r.value("limit", 100),
                     r.value("offset", 0));
    if (op == "detail")
        return detail(r.at("id"));
    if (op == "annotate") {
        annotate(r.at("id"), r.at("author"), r.value("text", std::string{}), r.at("status"));
        return {{"ok", true}};
    }
    if (op == "get")
        return get(r.at("table"), r.at("key"));
    if (op == "put") {
        put(r.at("table"), r.at("key"), r.at("data"), r.value("expires_ms", Millis{}));
        return {{"ok", true}};
    }
    if (op == "audit") {
        audit(r.at("author"), r.at("data"));
        return {{"ok", true}};
    }
    if (op == "health")
        return health();
    if (op == "retention")
        return retention(r.value("now", utcNow()), r.value("event_days", 14), r.value("incident_days", 90),
                         r.value("spool_days", 7));
    if (op == "flush") {
        checkpoint();
        return {{"ok", true}};
    }
    throw std::runtime_error("unsupported store operation");
}
StoreWorker::StoreWorker(const std::string &path, std::size_t capacity, std::uint64_t maxBytes)
    : capacity_(capacity) {
    if (capacity < 1 || capacity > 100000)
        throw std::runtime_error("invalid storage queue capacity");
    auto started = std::make_shared<std::promise<void>>();
    auto startup = started->get_future();
    thread_ = std::jthread([this, path, maxBytes, started] {
        try {
            SqliteStore store(path, maxBytes);
            started->set_value();
            for (;;) {
                Work work;
                {
                    std::unique_lock lock(mutex_);
                    ready_.wait(lock, [&] { return closing_ || !queue_.empty(); });
                    if (queue_.empty() && closing_)
                        break;
                    work = std::move(queue_.front());
                    queue_.pop_front();
                }
                try {
                    auto began = std::chrono::steady_clock::now();
                    auto result = store.request(work.request);
                    ++processed_;
                    lastMicros_ = std::chrono::duration_cast<std::chrono::microseconds>(
                                      std::chrono::steady_clock::now() - began)
                                      .count();
                    if (work.result)
                        work.result->set_value(std::move(result));
                } catch (...) {
                    ++failures_;
                    if (work.result)
                        work.result->set_exception(std::current_exception());
                }
            }
            store.checkpoint();
        } catch (...) {
            try {
                started->set_exception(std::current_exception());
            } catch (...) {
            }
            ++failures_;
        }
    });
    startup.get();
}
StoreWorker::~StoreWorker() {
    {
        std::lock_guard lock(mutex_);
        closing_ = true;
    }
    ready_.notify_all();
    if (thread_.joinable())
        thread_.join();
}
bool StoreWorker::enqueue(Json request) {
    std::lock_guard lock(mutex_);
    if (closing_ || queue_.size() >= capacity_) {
        ++dropped_;
        return false;
    }
    queue_.push_back({std::move(request), {}});
    ready_.notify_one();
    return true;
}
std::future<Json> StoreWorker::submit(Json request) {
    auto promise = std::make_shared<std::promise<Json>>();
    auto future = promise->get_future();
    {
        std::lock_guard lock(mutex_);
        if (closing_ || queue_.size() >= capacity_) {
            ++dropped_;
            promise->set_exception(
                std::make_exception_ptr(std::runtime_error("storage queue unavailable/full")));
            return future;
        }
        queue_.push_back({std::move(request), promise});
    }
    ready_.notify_one();
    return future;
}
Json StoreWorker::call(Json request) {
    bool health = request.value("op", std::string{}) == "health";
    auto future = submit(std::move(request));
    if (future.wait_for(std::chrono::seconds(15)) != std::future_status::ready)
        throw std::runtime_error("storage request timeout");
    auto result = future.get();
    if (health)
        result["writer"] = stats();
    return result;
}
Json StoreWorker::stats() {
    std::lock_guard lock(mutex_);
    return {{"queue_depth", queue_.size()},
            {"queue_limit", capacity_},
            {"processed_requests", processed_.load()},
            {"last_request_us", lastMicros_.load()},
            {"dropped", dropped_.load()},
            {"failures", failures_.load()}};
}
void StoreWorker::flush() {
    call({{"op", "flush"}});
    if (failures_)
        throw std::runtime_error("storage writes failed: " + std::to_string(failures_.load()));
}
} // namespace irforge
