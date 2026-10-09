#include "irforge/remote/TlsTransport.hpp"
#include "irforge/cli/Commands.hpp"
#include "irforge/ipc/PipeServer.hpp"
#include "irforge/monitoring/Win32.hpp"
#include "irforge/reporting/Evidence.hpp"
#include "irforge/ti/VirusTotal.hpp"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QHostAddress>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslServer>
#include <QSslSocket>
#include <QTimer>
#include <QUrl>
#include <charconv>
#include <compressapi.h>
#include <fstream>
#include <iostream>
#include <set>
namespace irforge {
namespace {
QByteArray compressMetadata(const QByteArray &input) {
    COMPRESSOR_HANDLE handle = nullptr;
    if (!CreateCompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &handle))
        throw WindowsError(GetLastError(), "metadata compressor");
    struct Close {
        COMPRESSOR_HANDLE h;
        ~Close() { CloseCompressor(h); }
    } cleanup{handle};
    SIZE_T capacity = 0;
    Compress(handle, const_cast<char *>(input.constData()), static_cast<SIZE_T>(input.size()), nullptr, 0,
             &capacity);
    if (capacity > 1048576)
        return input;
    QByteArray output(static_cast<qsizetype>(capacity), Qt::Uninitialized);
    SIZE_T written = 0;
    if (!Compress(handle, const_cast<char *>(input.constData()), static_cast<SIZE_T>(input.size()),
                  output.data(), capacity, &written))
        throw WindowsError(GetLastError(), "compress metadata");
    output.resize(static_cast<qsizetype>(written));
    return output;
}
QByteArray decompressMetadata(const QByteArray &input) {
    DECOMPRESSOR_HANDLE handle = nullptr;
    if (!CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &handle))
        throw WindowsError(GetLastError(), "metadata decompressor");
    struct Close {
        DECOMPRESSOR_HANDLE h;
        ~Close() { CloseDecompressor(h); }
    } cleanup{handle};
    SIZE_T expected = 0;
    Decompress(handle, const_cast<char *>(input.constData()), static_cast<SIZE_T>(input.size()), nullptr, 0,
               &expected);
    if (expected == 0 || expected > 1048576)
        throw std::runtime_error("compressed input expansion limit");
    QByteArray output(static_cast<qsizetype>(expected), Qt::Uninitialized);
    SIZE_T written = 0;
    if (!Decompress(handle, const_cast<char *>(input.constData()), static_cast<SIZE_T>(input.size()),
                    output.data(), expected, &written) ||
        written != expected)
        throw std::runtime_error("invalid compressed metadata");
    return output;
}
QString q(const std::string &s) { return QString::fromUtf8(s.data(), static_cast<qsizetype>(s.size())); }
std::string s(const QByteArray &v) { return {v.constData(), static_cast<std::size_t>(v.size())}; }
Json parse(const std::string &wire) {
    if (wire.size() > 1048576)
        throw std::runtime_error("remote body exceeds 1 MiB");
    auto j = Json::parse(wire, [](int depth, Json::parse_event_t, Json &) {
        if (depth > 32)
            throw std::runtime_error("remote JSON nesting exceeds 32");
        return true;
    });
    validateDocument(j);
    return j;
}
QSslConfiguration configuration(const Json &config) {
    validateDocument(config);
    QFile ca(q(config.at("ca_file").get<std::string>()));
    if (!ca.open(QIODevice::ReadOnly) || ca.size() > 1048576)
        throw std::runtime_error("CA file missing or exceeds size limit");
    auto authorities = QSslCertificate::fromData(ca.readAll(), QSsl::Pem);
    if (authorities.empty() || authorities.size() > 32)
        throw std::runtime_error("CA certificate file invalid");
    QFile identity(q(config.at("identity_pfx").get<std::string>()));
    if (!identity.open(QIODevice::ReadOnly) || identity.size() > 1048576)
        throw std::runtime_error("identity PFX missing or exceeds size limit");
    std::string secret = config.contains("credential_target")
                             ? loadTiCredential(config.at("credential_target").get<std::string>())
                             : std::string{};
    QSslKey key;
    QSslCertificate certificate;
    QList<QSslCertificate> chain;
    bool imported =
        QSslCertificate::importPkcs12(&identity, &key, &certificate, &chain,
                                      QByteArray(secret.data(), static_cast<qsizetype>(secret.size())));
    std::fill(secret.begin(), secret.end(), '\0');
    if (!imported || key.isNull() || certificate.isNull())
        throw std::runtime_error("PFX import failed; use Credential Manager for encrypted identity password");
    QSslConfiguration ssl;
    ssl.setProtocol(QSsl::TlsV1_2OrLater);
    ssl.setPeerVerifyMode(QSslSocket::VerifyPeer);
    ssl.setPeerVerifyDepth(6);
    ssl.setCaCertificates(authorities);
    ssl.setPrivateKey(key);
    if (chain.empty() || chain.front() != certificate)
        chain.prepend(certificate);
    ssl.setLocalCertificateChain(chain);
    return ssl;
}
struct Http {
    std::string first;
    std::map<std::string, std::string> headers;
    std::size_t length = 0, bodyAt = 0;
};
std::optional<Http> httpHeader(const QByteArray &wire) {
    auto position = wire.indexOf("\r\n\r\n");
    if (position < 0) {
        if (wire.size() > 16384)
            throw std::runtime_error("HTTP headers exceed 16 KiB");
        return {};
    }
    if (position > 16384)
        throw std::runtime_error("HTTP headers exceed 16 KiB");
    auto header = s(wire.left(position));
    Http result;
    std::size_t at = header.find("\r\n");
    result.first = header.substr(0, at);
    if (result.first.size() > 4096)
        throw std::runtime_error("HTTP request line bound");
    if (at == std::string::npos)
        throw std::runtime_error("HTTP headers missing");
    at += 2;
    while (at < header.size()) {
        auto end = header.find("\r\n", at);
        auto row = header.substr(at, end - at);
        auto colon = row.find(':');
        if (colon == std::string::npos)
            throw std::runtime_error("malformed HTTP header");
        auto key = lower(row.substr(0, colon)), value = row.substr(colon + 1);
        while (!value.empty() && value.front() == ' ')
            value.erase(0, 1);
        if (key.empty() || result.headers.contains(key))
            throw std::runtime_error("duplicate HTTP header");
        result.headers[key] = value;
        if (end == std::string::npos)
            break;
        at = end + 2;
    }
    if (result.headers.contains("transfer-encoding"))
        throw std::runtime_error("chunked remote requests are unsupported");
    if (!result.headers.contains("content-length"))
        throw std::runtime_error("Content-Length required");
    auto text = result.headers["content-length"];
    auto parsed = std::from_chars(text.data(), text.data() + text.size(), result.length);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || result.length > 1048576)
        throw std::runtime_error("invalid remote body length");
    result.bodyAt = static_cast<std::size_t>(position) + 4;
    return result;
}
void writeResponse(QSslSocket &socket, int code, const Json &result) {
    auto body = result.dump();
    if (body.size() > 1048576)
        throw std::runtime_error("remote response too large; reduce page size");
    auto header = "HTTP/1.1 " + std::to_string(code) + (code == 200 ? " OK" : " Rejected") +
                  "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
                  "\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n";
    socket.write(QByteArray(header.data(), static_cast<qsizetype>(header.size())));
    socket.write(QByteArray(body.data(), static_cast<qsizetype>(body.size())));
    socket.disconnectFromHost();
}
} // namespace
Json tlsRequest(const Json &config, const std::string &path, const Json &body) {
    if (path != "/v1/batch" && path != "/v1/query" && path != "/v1/enrollment" && path != "/v1/heartbeat")
        throw std::runtime_error("remote endpoint is not allowed");
    validateDocument(body);
    auto ssl = configuration(config);
    QUrl url(q(config.at("collector_url").get<std::string>()), QUrl::StrictMode);
    if (!url.isValid() || url.scheme() != "https" || url.host().isEmpty() || !url.userName().isEmpty() ||
        !url.password().isEmpty() || url.hasQuery() || url.hasFragment() ||
        (!url.path().isEmpty() && url.path() != "/"))
        throw std::runtime_error("collector URL must be a bare verified HTTPS origin");
    QSslSocket socket;
    socket.setSslConfiguration(ssl);
    socket.setPeerVerifyName(url.host());
    socket.connectToHostEncrypted(url.host(), static_cast<quint16>(url.port(443)));
    if (!socket.waitForEncrypted(5000))
        throw std::runtime_error("mTLS handshake failed: " + s(socket.errorString().toUtf8()));
    auto fingerprint = s(socket.peerCertificate().digest(QCryptographicHash::Sha256).toHex());
    if (config.contains("server_fingerprint") &&
        lower(config.at("server_fingerprint").get<std::string>()) != fingerprint)
        throw std::runtime_error("collector certificate pin mismatch");
    auto json = body.dump();
    QByteArray payload(json.data(), static_cast<qsizetype>(json.size()));
    bool compressed = path == "/v1/batch" && payload.size() > 4096 && config.value("compression", true);
    if (compressed) {
        auto candidate = compressMetadata(payload);
        if (candidate.size() < payload.size())
            payload = candidate;
        else
            compressed = false;
    }
    auto request = "POST " + path + " HTTP/1.1\r\nHost: " + s(url.host().toUtf8()) +
                   "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(payload.size()) +
                   (compressed ? "\r\nContent-Encoding: x-irforge-xpress-v1" : "") +
                   "\r\nConnection: close\r\n\r\n" + s(payload);
    if (socket.write(QByteArray(request.data(), static_cast<qsizetype>(request.size()))) < 0 ||
        !socket.waitForBytesWritten(5000))
        throw std::runtime_error("TLS request write failed");
    QByteArray response;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    std::optional<Http> header;
    while (std::chrono::steady_clock::now() < deadline) {
        response += socket.readAll();
        if (response.size() > 1048576 + 16384)
            throw std::runtime_error("remote response limit");
        if (!header)
            header = httpHeader(response);
        if (header && response.size() >= static_cast<qsizetype>(header->bodyAt + header->length)) {
            if (response.size() != static_cast<qsizetype>(header->bodyAt + header->length))
                throw std::runtime_error("unexpected remote trailing bytes");
            auto result = parse(s(response.mid(static_cast<qsizetype>(header->bodyAt))));
            if (!header->first.starts_with("HTTP/1.1 200 "))
                throw std::runtime_error("remote request rejected: " +
                                         result.value("error", std::string("HTTP error")));
            return result;
        }
        if (socket.state() == QAbstractSocket::UnconnectedState)
            throw std::runtime_error("collector closed incomplete response");
        socket.waitForReadyRead(100);
    }
    throw std::runtime_error("collector response deadline exceeded");
}
struct RemoteSender::Impl {
    StoreWorker &store;
    Json connection;
    std::jthread worker;
    Impl(StoreWorker &s, Json c) : store(s), connection(std::move(c)) {
        configuration(connection);
        worker = std::jthread([this](std::stop_token stop) {
            int backoff = 1;
            auto nextHeartbeat = std::chrono::steady_clock::time_point{};
            while (!stop.stop_requested()) {
                Json health;
                try {
                    auto batch = store.call({{"op", "spool_next"}, {"limit", 100}});
                    if (!batch["packets"].empty()) {
                        auto response = tlsRequest(connection, "/v1/batch", batch);
                        if (response.at("agent_id") != batch["packets"][0]["agent_id"] ||
                            response.at("session_id") != batch["packets"][0]["session_id"])
                            throw std::runtime_error("ACK agent/session mismatch");
                        auto ack = response.at("ack_sequence").get<std::uint64_t>();
                        if (ack < batch["packets"].back().at("sequence").get<std::uint64_t>())
                            throw std::runtime_error("collector did not durably ACK entire batch");
                        store.call({{"op", "spool_ack"},
                                    {"agent_id", response["agent_id"]},
                                    {"session_id", response["session_id"]},
                                    {"sequence", ack}});
                    }
                    health = {{"state", "connected_or_idle"},
                              {"last_check", formatUtc(utcNow())},
                              {"metadata_only", true}};
                    auto identity =
                        store.call({{"op", "get"}, {"table", "settings"}, {"key", "remote/config"}});
                    if (identity.contains("host_id") && std::chrono::steady_clock::now() >= nextHeartbeat) {
                        tlsRequest(connection, "/v1/heartbeat",
                                   {{"schema_version", 1},
                                    {"agent_id", identity["agent_id"]},
                                    {"host_id", identity["host_id"]},
                                    {"metadata_only", true}});
                        nextHeartbeat = std::chrono::steady_clock::now() + std::chrono::seconds(30);
                    }
                    backoff = 1;
                } catch (const std::exception &e) {
                    health = {{"state", "retrying"},
                              {"reason", e.what()},
                              {"last_check", formatUtc(utcNow())},
                              {"metadata_only", true}};
                    backoff = std::min(backoff * 2, 60);
                }
                try {
                    store.call(
                        {{"op", "put"}, {"table", "health"}, {"key", "remote_transport"}, {"data", health}});
                } catch (...) {
                }
                const int jitter = static_cast<int>(utcNow() % 10);
                for (int i = 0; i < backoff * 10 + jitter && !stop.stop_requested(); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        });
    }
};
RemoteSender::RemoteSender(StoreWorker &s, const Json &c) : impl_(std::make_unique<Impl>(s, c)) {}
RemoteSender::~RemoteSender() { stop(); }
void RemoteSender::stop() noexcept {
    if (impl_ && impl_->worker.joinable()) {
        impl_->worker.request_stop();
        impl_->worker.join();
    }
}
std::optional<int> remoteCommand(const std::vector<std::string> &args) {
    if (args.size() < 2 || args[1] != "remote")
        return {};
    if (args.size() < 3)
        throw std::runtime_error("remote requires configure/send/query");
    Arguments options(args, 3, {"--db", "--config", "--agent-id", "--host", "--table", "--incident"},
                      {"--confirm"});
    auto action = args[2];
    if (action == "status" || action == "disconnect") {
        StoreWorker store(options.require("--db"));
        auto config = store.call({{"op", "get"}, {"table", "settings"}, {"key", "remote/config"}});
        if (action == "disconnect") {
            if (!options.has("--confirm"))
                throw std::runtime_error("remote disconnect requires --confirm");
            config["enabled"] = false;
            store.call({{"op", "put"}, {"table", "settings"}, {"key", "remote/config"}, {"data", config}});
            store.call({{"op", "audit"},
                        {"author", "local remote operator"},
                        {"data", {{"operation", "remote_disconnect"}}}});
        }
        std::cout << config.dump(2) << '\n';
        return 0;
    }
    auto config = readJsonFile(options.require("--config"));
    if (action == "query") {
        Json request = options.has("--incident") ? Json{{"op", "detail"}, {"id", options.get("--incident")}}
                                                 : Json{{"op", "query"},
                                                        {"table", options.get("--table", "incidents")},
                                                        {"filters", {{"host", options.require("--host")}}},
                                                        {"limit", 50}};
        std::cout << tlsRequest(config, "/v1/query", request).dump(2) << '\n';
        return 0;
    }
    StoreWorker store(options.require("--db"));
    if (action == "configure" || action == "enroll") {
        if (!options.has("--confirm"))
            throw std::runtime_error("remote configure requires --confirm; metadata is sent only when sender "
                                     "is explicitly enabled");
        auto agent = options.require("--agent-id");
        store.call({{"op", "put"},
                    {"table", "settings"},
                    {"key", "remote/config"},
                    {"data",
                     {{"enabled", true},
                      {"agent_id", agent},
                      {"host_id", options.get("--host", stableHostId())},
                      {"redact_command_lines", true},
                      {"max_items", 10000},
                      {"max_bytes", 128ULL * 1048576}}}});
        store.call({{"op", "audit"},
                    {"author", "local remote operator"},
                    {"data",
                     {{"operation", "remote_configure"},
                      {"agent_id", agent},
                      {"url", config.at("collector_url")}}}});
        return 0;
    }
    if (action == "send") {
        auto batch = store.call({{"op", "spool_next"}, {"limit", 100}});
        if (batch["packets"].empty()) {
            std::cout << "No pending metadata\n";
            return 0;
        }
        auto response = tlsRequest(config, "/v1/batch", batch);
        if (response.at("agent_id") != batch["packets"][0]["agent_id"] ||
            response.at("session_id") != batch["packets"][0]["session_id"] ||
            response.at("ack_sequence").get<std::uint64_t>() <
                batch["packets"].back().at("sequence").get<std::uint64_t>())
            throw std::runtime_error("ACK does not cover requested agent/session batch");
        store.call({{"op", "spool_ack"},
                    {"agent_id", response.at("agent_id")},
                    {"session_id", response.at("session_id")},
                    {"sequence", response.at("ack_sequence")}});
        std::cout << response.dump(2) << '\n';
        return 0;
    }
    throw std::runtime_error("unsupported remote action");
}
int collectorApplication(const std::vector<std::string> &args) {
    if (args.size() < 2)
        throw std::runtime_error("collector requires serve/enroll/revoke/status");
    auto action = args[1];
    Arguments options(args, 2,
                      {"--config", "--db", "--fingerprint", "--agent-id", "--host-id", "--role",
                       "--allowed-hosts", "--duration-seconds"},
                      {"--confirm", "--allow-network"});
    if (action == "enroll" || action == "revoke" || action == "status") {
        StoreWorker store(options.require("--db"));
        auto fingerprint = lower(options.require("--fingerprint"));
        auto key = "remote/enrollment/" + fingerprint;
        auto existing = store.call({{"op", "get"}, {"table", "settings"}, {"key", key}});
        if (action == "status") {
            std::cout << existing.dump(2) << '\n';
            return 0;
        }
        if (!options.has("--confirm"))
            throw std::runtime_error("enrollment changes require explicit --confirm");
        Json enrollment;
        if (action == "revoke") {
            if (existing.is_null())
                throw std::runtime_error("certificate is not enrolled");
            enrollment = existing;
            enrollment["revoked"] = true;
        } else {
            std::vector<std::string> hosts;
            auto text = options.get("--allowed-hosts");
            std::size_t at = 0;
            while (at < text.size()) {
                auto end = text.find(',', at);
                hosts.push_back(text.substr(at, end - at));
                if (end == std::string::npos)
                    break;
                at = end + 1;
            }
            enrollment = {{"schema_version", 1},
                          {"fingerprint", fingerprint},
                          {"agent_id", options.require("--agent-id")},
                          {"host_id", options.require("--host-id")},
                          {"role", options.get("--role", "agent")},
                          {"allowed_hosts", hosts},
                          {"revoked", false}};
            validateEnrollment(enrollment);
        }
        store.call({{"op", "put"}, {"table", "settings"}, {"key", key}, {"data", enrollment}});
        store.call({{"op", "audit"},
                    {"author", "local PKI operator"},
                    {"data", {{"operation", "certificate_" + action}, {"enrollment", enrollment}}}});
        std::cout << enrollment.dump(2) << '\n';
        return 0;
    }
    if (action != "serve")
        throw std::runtime_error("unsupported collector action");
    auto config = readJsonFile(options.require("--config"));
    auto ssl = configuration(config);
    QHostAddress bind(q(config.value("bind", std::string("127.0.0.1"))));
    if (bind.isNull() || (!bind.isLoopback() && !options.has("--allow-network")))
        throw std::runtime_error("network listener requires an explicit bind address and --allow-network");
    int port = config.value("port", 8443);
    if (port < 1 || port > 65535)
        throw std::runtime_error("collector port bound");
    auto db = config.at("database").get<std::string>();
    auto parent = filesystemPath(db).parent_path();
    if (!std::filesystem::exists(parent))
        privateDirectory(parent.string(), true);
    StoreWorker store(db);
    QSslServer server;
    server.setSslConfiguration(ssl);
    server.setHandshakeTimeout(5000);
    server.setMaxPendingConnections(16);
    if (!server.listen(bind, static_cast<quint16>(port)))
        throw std::runtime_error("TLS listener failed: " + s(server.errorString().toUtf8()));
    OperationGateway gateway(store, config.value("rules_dir", std::string("rules/internal")));
    PipeServer pipe(config.value("pipe_name", std::string("IRForge.Collector.v1")), gateway);
    pipe.start();
    int activeConnections = 0;
    QObject::connect(&server, &QTcpServer::pendingConnectionAvailable, &server, [&] {
        while (server.hasPendingConnections()) {
            auto *socket = qobject_cast<QSslSocket *>(server.nextPendingConnection());
            if (!socket)
                continue;
            if (activeConnections >= 32) {
                socket->abort();
                socket->deleteLater();
                continue;
            }
            ++activeConnections;
            QObject::connect(socket, &QObject::destroyed, &server, [&] { --activeConnections; });
            if (!socket->isEncrypted() || socket->peerCertificate().isNull()) {
                socket->abort();
                socket->deleteLater();
                continue;
            }
            auto buffer = std::make_shared<QByteArray>();
            auto handled = std::make_shared<bool>(false);
            auto *timer = new QTimer(socket);
            timer->setSingleShot(true);
            timer->setInterval(10000);
            QObject::connect(timer, &QTimer::timeout, socket, [socket] { socket->abort(); });
            timer->start();
            QObject::connect(socket, &QAbstractSocket::disconnected, socket, &QObject::deleteLater);
            auto read = [&, socket, buffer, handled, timer] {
                if (*handled)
                    return;
                try {
                    *buffer += socket->readAll();
                    if (buffer->size() > 1048576 + 16384)
                        throw std::runtime_error("remote request exceeds limit");
                    auto header = httpHeader(*buffer);
                    if (!header || buffer->size() < static_cast<qsizetype>(header->bodyAt + header->length))
                        return;
                    if (buffer->size() != static_cast<qsizetype>(header->bodyAt + header->length))
                        throw std::runtime_error("pipelined/trailing requests rejected");
                    if (header->headers["content-type"] != "application/json")
                        throw std::runtime_error("application/json metadata required");
                    *handled = true;
                    timer->stop();
                    auto fingerprint =
                        s(socket->peerCertificate().digest(QCryptographicHash::Sha256).toHex());
                    auto enrollment = store.call(
                        {{"op", "get"}, {"table", "settings"}, {"key", "remote/enrollment/" + fingerprint}});
                    if (enrollment.is_null() || enrollment.value("revoked", true)) {
                        writeResponse(*socket, 403,
                                      {{"error", "client certificate is not enrolled or is revoked"}});
                        return;
                    }
                    auto encoded = buffer->mid(static_cast<qsizetype>(header->bodyAt));
                    if (header->headers.contains("content-encoding")) {
                        if (header->headers["content-encoding"] != "x-irforge-xpress-v1")
                            throw std::runtime_error("unsupported compression framing");
                        encoded = decompressMetadata(encoded);
                    }
                    auto body = parse(s(encoded));
                    Json result;
                    if (header->first == "POST /v1/batch HTTP/1.1")
                        result = acceptRemoteBatch(store, body, enrollment);
                    else if (header->first == "POST /v1/heartbeat HTTP/1.1") {
                        if (enrollment["role"] != "agent" || body.at("schema_version") != 1 ||
                            body.at("agent_id") != enrollment["agent_id"] ||
                            body.at("host_id") != enrollment["host_id"])
                            throw std::runtime_error("heartbeat certificate binding rejected");
                        result = {{"host_id", enrollment["host_id"]},
                                  {"agent_id", enrollment["agent_id"]},
                                  {"last_seen", formatUtc(utcNow())},
                                  {"identity", "verified mTLS"},
                                  {"observation_health",
                                   "source agent heartbeat; not independent collector validation"}};
                        store.call({{"op", "put"},
                                    {"table", "health"},
                                    {"key", "remote/" + enrollment.at("host_id").get<std::string>()},
                                    {"data", result}});
                    } else if (header->first == "POST /v1/query HTTP/1.1")
                        result = remoteRead(store, body, enrollment);
                    else if (header->first == "POST /v1/enrollment HTTP/1.1") {
                        if (enrollment["role"] != "admin")
                            throw std::runtime_error("enrollment changes require admin certificate role");
                        validateEnrollment(body);
                        store.call(
                            {{"op", "put"},
                             {"table", "settings"},
                             {"key", "remote/enrollment/" + lower(body.at("fingerprint").get<std::string>())},
                             {"data", body}});
                        store.call({{"op", "audit"},
                                    {"author", "certificate " + fingerprint},
                                    {"data", {{"operation", "certificate_change"}, {"enrollment", body}}}});
                        result = {{"updated", true}};
                    } else
                        throw std::runtime_error(
                            "unknown endpoint; remote commands and file transfers are not supported");
                    writeResponse(*socket, 200, result);
                } catch (const std::exception &e) {
                    *handled = true;
                    timer->stop();
                    try {
                        writeResponse(*socket, 400, {{"error", e.what()}});
                    } catch (...) {
                        socket->abort();
                    }
                }
            };
            QObject::connect(socket, &QIODevice::readyRead, socket, read);
            read();
        }
    });
    int duration = options.integer("--duration-seconds", 0, 0, 86400);
    if (duration)
        QTimer::singleShot(duration * 1000, QCoreApplication::instance(), &QCoreApplication::quit);
    std::cout << Json{{"state", "listening"}, {"bind", config.value("bind", std::string("127.0.0.1"))},
                      {"port", port},         {"tls_backend", s(QSslSocket::activeBackend().toUtf8())},
                      {"mutual_tls", true},   {"metadata_only", true},
                      {"database", db}}
                     .dump()
              << std::endl;
    int result = QCoreApplication::exec();
    server.close();
    pipe.stop();
    store.flush();
    return result;
}
} // namespace irforge
