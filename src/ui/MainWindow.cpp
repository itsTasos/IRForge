#include "MainWindow.hpp"
#include "ControlPanel.hpp"
#include "irforge/enrichment/HashEngine.hpp"
#include "irforge/ipc/PipeServer.hpp"
#include "irforge/monitoring/Win32.hpp"
#include "irforge/reporting/Evidence.hpp"
#include "irforge/reporting/ReportExporter.hpp"
#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGraphicsScene>
#include <QGraphicsTextItem>
#include <QGraphicsView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPdfWriter>
#include <QPointer>
#include <QPushButton>
#include <QSettings>
#include <QShortcut>
#include <QSpinBox>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextBrowser>
#include <QTextDocument>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
#include <QtConcurrent>
#include <fstream>
#include <shellapi.h>
namespace irforge {
namespace {
QString q(const std::string &s) { return QString::fromUtf8(s.data(), static_cast<qsizetype>(s.size())); }
std::string s(const QString &v) {
    auto bytes = v.toUtf8();
    return {bytes.constData(), static_cast<std::size_t>(bytes.size())};
}
QString value(const Json &j, const std::string &path) {
    const Json *p = &j;
    std::size_t start = 0;
    for (;;) {
        auto end = path.find('.', start);
        auto key = path.substr(start, end - start);
        if (!p->is_object() || !p->contains(key))
            return "Unknown";
        p = &p->at(key);
        if (end == std::string::npos)
            break;
        start = end + 1;
    }
    if (p->is_null())
        return "Unknown";
    return q(p->is_string() ? p->get<std::string>() : p->dump());
}
QTextBrowser *document(const Json &data) {
    auto *view = new QTextBrowser;
    view->setOpenExternalLinks(false);
    view->setPlainText(q(data.dump(2)));
    return view;
}
const QStringList pages = {
    "Overview",  "Incidents",      "Processes",       "Event Timeline",      "Persistence",
    "Artifacts", "Rules",          "Hosts and Cases", "Threat Intelligence", "Settings and Health",
    "Baselines", "Threat Hunting", "Network"};
} // namespace
void MainWindow::mutate(const Json &request, const std::function<void(const Json &)> &completed) {
    auto pipe = pipe_;
    if (administrator_) {
        async([pipe, request] { return pipeRequest(pipe, request); }, completed);
        return;
    }
    // User-selected mutations invoke the standard visible Windows UAC prompt.
    auto helper = s(QCoreApplication::applicationDirPath() + "/irforge.exe");
    async(
        [pipe, request, helper] {
            auto folder =
                std::filesystem::temp_directory_path() / filesystemPath("IRForgeLab-request-" + newUuid());
            privateDirectory(folder.string(), true);
            auto file = folder / "request.json";
            struct Cleanup {
                std::filesystem::path file, folder;
                ~Cleanup() {
                    std::error_code ec;
                    std::filesystem::remove(file, ec);
                    std::filesystem::remove(folder, ec);
                }
            } cleanup{file, folder};
            writeDocument(file, request);
            auto digest = hashFile(file.string(), 1048576);
            if (digest.status != "complete")
                throw std::runtime_error("cannot seal administrator request");
            auto arguments = utf16("agent request --pipe \"" + pipe + "\" --request \"" + file.string() +
                                   "\" --sha256 " + digest.sha256 + " --confirm");
            auto executable = utf16(helper);
            SHELLEXECUTEINFOW action{};
            action.cbSize = sizeof(action);
            action.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
            action.lpVerb = L"runas";
            action.lpFile = executable.c_str();
            action.lpParameters = arguments.c_str();
            action.nShow = SW_HIDE;
            if (!ShellExecuteExW(&action))
                throw WindowsError(GetLastError(), "administrator action cancelled or unavailable");
            Handle process(action.hProcess);
            if (WaitForSingleObject(process.value, 30000) != WAIT_OBJECT_0)
                throw std::runtime_error("administrator action deadline exceeded");
            DWORD code = 1;
            GetExitCodeProcess(process.value, &code);
            if (code)
                throw std::runtime_error("administrator action rejected; check agent diagnostics");
            return Json{{"applied", true}, {"authorization", "explicit Windows UAC helper"}};
        },
        completed);
}
MainWindow::MainWindow(std::string pipe) : pipe_(std::move(pipe)) {
    setWindowTitle("IRForge — local evidence and incident triage");
    resize(1360, 900);
    setMinimumSize(980, 640);
    auto *root = new QWidget;
    auto *layout = new QVBoxLayout(root);
    layout->setContentsMargins(20, 16, 20, 16);
    layout->setSpacing(12);
    auto *header = new QHBoxLayout;
    auto *brand = new QVBoxLayout;
    auto *heading = new QLabel("IRForge");
    heading->setObjectName("brandTitle");
    auto *notice = new QLabel("ENDPOINT EVIDENCE  /  INVESTIGATION CONSOLE");
    notice->setObjectName("brandSubtitle");
    brand->addWidget(heading);
    brand->addWidget(notice);
    brand->setSpacing(2);
    header->addLayout(brand);
    header->addStretch();
    auto *control = new QPushButton("Monitoring setup and control");
    control->setObjectName("primaryAction");
    header->addWidget(control);
    layout->addLayout(header);
    connect(control, &QPushButton::clicked, this, [this] { openControlPanel(); });
    auto *split = new QSplitter;
    navigation_ = new QListWidget;
    navigation_->setObjectName("navigation");
    navigation_->addItems(pages);
    navigation_->setMinimumWidth(200);
    navigation_->setMaximumWidth(230);
    split->addWidget(navigation_);
    auto *content = new QWidget;
    auto *body = new QVBoxLayout(content);
    body->setContentsMargins(16, 0, 0, 0);
    body->setSpacing(10);
    auto *pageTitle = new QLabel("Overview");
    pageTitle->setObjectName("pageTitle");
    body->addWidget(pageTitle);
    summary_ = new QLabel("Connecting to local agent…");
    summary_->setWordWrap(true);
    summary_->setTextFormat(Qt::PlainText);
    body->addWidget(summary_);
    auto *filters = new QHBoxLayout;
    search_ = new QLineEdit;
    search_->setPlaceholderText("Search stored evidence");
    host_ = new QLineEdit;
    host_->setPlaceholderText("Host ID");
    pid_ = new QLineEdit;
    pid_->setPlaceholderText("PID (events)");
    severity_ = new QComboBox;
    severity_->addItems({"Any severity", "informational", "low", "medium", "high", "critical"});
    state_ = new QComboBox;
    state_->addItems({"Any state", "new", "investigating", "benign", "resolved"});
    auto *refreshButton = new QPushButton("Refresh");
    filters->addWidget(search_, 3);
    filters->addWidget(host_, 2);
    filters->addWidget(pid_);
    filters->addWidget(severity_);
    filters->addWidget(state_);
    filters->addWidget(refreshButton);
    body->addLayout(filters);
    auto *eventFilters = new QHBoxLayout;
    type_ = new QComboBox;
    type_->addItem("Any event type");
    for (int i = 0; i <= static_cast<int>(EventType::Unmapped); ++i)
        type_->addItem(q(eventTypeName(static_cast<EventType>(i))));
    source_ = new QComboBox;
    source_->addItems({"Any source", "process_etw", "network", "registry", "filesystem_diff", "inventory",
                       "sysmon", "windows_eventlog", "yara", "baseline", "threat_intel"});
    auto *localTime = new QCheckBox("Local time");
    auto *theme = new QCheckBox("Dark theme");
    auto *saveQuery = new QPushButton("Save search");
    auto *loadQuery = new QPushButton("Load search");
    auto *exportRows = new QPushButton("Export this page");
    eventFilters->addWidget(type_);
    eventFilters->addWidget(source_);
    eventFilters->addWidget(localTime);
    eventFilters->addWidget(theme);
    eventFilters->addWidget(saveQuery);
    eventFilters->addWidget(loadQuery);
    eventFilters->addWidget(exportRows);
    body->addLayout(eventFilters);
    auto *actions = new QHBoxLayout;
    auto *configure = new QPushButton("Agent settings");
    auto *lookup = new QPushButton("Reputation lookup");
    actions->addWidget(configure);
    actions->addWidget(lookup);
    actions->addStretch();
    body->addLayout(actions);
    connect(lookup, &QPushButton::clicked, this, [this] {
        bool ok = false;
        auto kind = QInputDialog::getItem(this, "Reputation lookup", "Indicator type", {"sha256", "ip"}, 0,
                                          false, &ok);
        if (!ok)
            return;
        auto indicator =
            QInputDialog::getText(this, "Explicit disclosure to VirusTotal",
                                  "Hash or public IP (no file is uploaded)", QLineEdit::Normal, "", &ok);
        if (!ok || indicator.trimmed().isEmpty())
            return;
        mutate(
            {{"op", "ti_lookup"}, {"kind", s(kind)}, {"indicator", s(indicator.trimmed())}, {"opt_in", true}},
            [this](const Json &) {
                summary_->setText("Reputation request queued. Results appear in Threat Intelligence and "
                                  "Settings / Health; missing credentials are reported there.");
            });
    });
    connect(configure, &QPushButton::clicked, this, [this] {
        auto pipe = pipe_;
        async([pipe] { return pipeRequest(pipe, {{"op", "health"}}); },
              [this](const Json &health) {
                  auto config = health.value("effective_config", Json(nullptr));
                  if (config.is_null()) {
                      summary_->setText("This evidence backend has no active collection configuration.");
                      return;
                  }
                  QDialog view(this);
                  view.setWindowTitle("Authorized collection settings — apply on next agent restart");
                  QVBoxLayout body(&view);
                  QFormLayout form;
                  std::vector<std::pair<std::string, QCheckBox *>> flags;
                  for (auto [key, label] : std::vector<std::pair<std::string, QString>>{
                           {"process_etw_enabled", "Process ETW"},
                           {"network_enabled", "TCP observations"},
                           {"registry_enabled", "Registry diffs"},
                           {"capture_command_line", "Capture command lines locally"},
                           {"file_monitor/enabled", "Explicit folder watcher"},
                           {"inventory/enabled", "Persistence inventory"},
                           {"windows_eventlog/enabled", "Event Log / Sysmon"},
                           {"yara/enabled", "Local YARA patterns"},
                           {"threat_intel/enabled", "Opt-in VirusTotal hash/public-IP lookup"},
                           {"privacy/redact_command_lines_for_remote", "Redact remote command lines"}}) {
                      auto *box = new QCheckBox;
                      auto slash = key.find('/');
                      bool checked = slash == std::string::npos
                                         ? config.value(key, false)
                                         : config.value(key.substr(0, slash), Json::object())
                                               .value(key.substr(slash + 1), key.starts_with("privacy/"));
                      box->setChecked(checked);
                      flags.push_back({key, box});
                      form.addRow(label, box);
                  }
                  auto *roots = new QLineEdit;
                  auto rootList =
                      config.value("file_monitor", Json::object()).value("roots", std::vector<std::string>{});
                  if (!rootList.empty())
                      roots->setText(q(rootList[0]));
                  form.addRow("First watch root (preserves additional roots)", roots);
                  auto *days = new QSpinBox;
                  days->setRange(1, 3650);
                  days->setValue(config.value("storage", Json::object()).value("retention_days", 14));
                  form.addRow("Event retention days", days);
                  body.addLayout(&form);
                  auto *notice =
                      new QLabel("Running source coverage changes after an explicit agent restart. Online "
                                 "lookups disclose only a hash or public IP; a credential must already be "
                                 "configured. Windows UAC authorizes this change.");
                  notice->setWordWrap(true);
                  body.addWidget(notice);
                  auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
                  body.addWidget(buttons);
                  connect(buttons, &QDialogButtonBox::rejected, &view, &QDialog::reject);
                  connect(
                      buttons, &QDialogButtonBox::accepted, &view,
                      [this, &view, config, flags, roots, days]() mutable {
                          for (auto &[key, box] : flags) {
                              auto slash = key.find('/');
                              if (slash == std::string::npos)
                                  config[key] = box->isChecked();
                              else
                                  config[key.substr(0, slash)][key.substr(slash + 1)] = box->isChecked();
                          }
                          if (!roots->text().trimmed().isEmpty()) {
                              auto list = config["file_monitor"].value("roots", std::vector<std::string>{});
                              if (list.empty())
                                  list.push_back(s(roots->text()));
                              else
                                  list[0] = s(roots->text());
                              config["file_monitor"]["roots"] = list;
                          }
                          config["storage"]["retention_days"] = days->value();
                          mutate({{"op", "configuration"}, {"config", config}}, [this](const Json &) {
                              summary_->setText(
                                  "Configuration saved for next agent start. Running coverage is unchanged.");
                          });
                          view.accept();
                      });
                  view.resize(800, 650);
                  view.exec();
              });
    });
    connect(localTime, &QCheckBox::toggled, this, [this](bool enabled) {
        localTime_ = enabled;
        refresh();
    });
    connect(theme, &QCheckBox::toggled, this, [](bool dark) {
        qApp->setStyleSheet(dark ? R"(
            QWidget { background:#101822; color:#d8e4eb; font-family:'Segoe UI'; font-size:13px; }
            QLabel { background:transparent; }
            QLabel#brandTitle { color:#e9f4f4; font-size:26px; font-weight:700; }
            QLabel#brandSubtitle { color:#8ba6b5; font-size:10px; font-weight:600; }
            QLabel#pageTitle { color:#edf5f7; font-size:23px; font-weight:650; }
            QListWidget#navigation { background:#151f2a; border:1px solid #263747; border-radius:8px; padding:6px; outline:0; }
            QListWidget#navigation::item { color:#abc0ca; padding:9px 12px; border-radius:4px; }
            QListWidget#navigation::item:hover { background:#1e303d; color:#edf6f6; }
            QListWidget#navigation::item:selected { background:#1d4248; color:#9ceee0; }
            QPushButton { background:#202f3b; color:#d7e8ec; border:1px solid #344a58; border-radius:5px; padding:8px 12px; }
            QPushButton:hover { background:#2a414c; border-color:#5b8d92; }
            QPushButton:pressed { background:#173c42; }
            QPushButton:disabled { background:#19242d; color:#6d818c; border-color:#283945; }
            QPushButton#primaryAction { background:#16796f; color:#ffffff; border:1px solid #238e81; font-weight:600; padding:10px 18px; }
            QPushButton#primaryAction:hover { background:#218d80; }
            QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit, QTextBrowser { background:#182632; color:#e2edf0; border:1px solid #344a58; border-radius:4px; padding:7px; selection-background-color:#277b78; }
            QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus { border:1px solid #65cabb; }
            QTableWidget { background:#141f29; alternate-background-color:#192732; border:1px solid #2b3c49; gridline-color:#273945; selection-background-color:#24535a; selection-color:white; }
            QTableWidget::item { padding:5px; }
            QHeaderView::section { background:#21323e; color:#b9cfd5; border:0; border-bottom:1px solid #354c58; padding:8px; font-weight:600; }
            QTabWidget::pane { border:1px solid #344a58; }
            QTabBar::tab { background:#182632; padding:9px 16px; color:#a9c0ca; }
            QTabBar::tab:selected { background:#27434b; color:#a4eee0; }
            QCheckBox { spacing:7px; } QCheckBox::indicator { width:15px; height:15px; }
            QSplitter::handle { background:#233642; }
            QScrollBar:vertical { background:#17232d; width:10px; } QScrollBar::handle:vertical { background:#405864; min-height:24px; border-radius:4px; }
        )"
                                 : R"(
            QWidget { background:#f3f7f8; color:#203640; font-family:'Segoe UI'; font-size:13px; }
            QLabel { background:transparent; } QLabel#brandTitle { font-size:26px; font-weight:700; color:#145f60; }
            QLabel#brandSubtitle { color:#526d77; font-size:10px; } QLabel#pageTitle { font-size:23px; font-weight:650; }
            QListWidget#navigation { background:#e5eff0; border:1px solid #c3d7db; padding:6px; }
            QListWidget#navigation::item { padding:9px 12px; } QListWidget#navigation::item:selected { background:#176d6b; color:white; }
            QPushButton { background:#e1edef; border:1px solid #b3cbd0; border-radius:5px; padding:8px 12px; }
            QPushButton:hover { background:#cfe3e4; } QPushButton#primaryAction { background:#147c73; color:white; font-weight:600; }
            QLineEdit,QComboBox,QSpinBox,QPlainTextEdit,QTextEdit,QTextBrowser,QTableWidget { background:white; color:#203640; border:1px solid #c0d4d8; padding:6px; }
            QHeaderView::section { background:#d9e8e9; color:#203640; padding:8px; border:0; }
        )");
    });
    theme->setChecked(true);
    auto *findShortcut = new QShortcut(QKeySequence::Find, this);
    connect(findShortcut, &QShortcut::activated, search_, qOverload<>(&QWidget::setFocus));
    auto *refreshShortcut = new QShortcut(QKeySequence::Refresh, this);
    connect(refreshShortcut, &QShortcut::activated, this, [this] { refresh(); });
    connect(saveQuery, &QPushButton::clicked, this, [this] {
        bool ok = false;
        auto name = QInputDialog::getText(this, "Save hunting query", "Name", QLineEdit::Normal, "", &ok);
        if (!ok || name.trimmed().isEmpty())
            return;
        QSettings settings("IRForge", "AnalystUI");
        settings.setValue("queries/" + name, QString::fromUtf8(Json{{"search", s(search_->text())},
                                                                    {"host", s(host_->text())},
                                                                    {"pid", s(pid_->text())},
                                                                    {"type", type_->currentIndex()},
                                                                    {"source", source_->currentIndex()}}
                                                                   .dump()));
        summary_->setText("Search saved to this analyst's local settings.");
    });
    connect(loadQuery, &QPushButton::clicked, this, [this] {
        QSettings settings("IRForge", "AnalystUI");
        settings.beginGroup("queries");
        auto names = settings.childKeys();
        bool ok = false;
        auto name = QInputDialog::getItem(this, "Load hunting query", "Saved search", names, 0, false, &ok);
        if (!ok)
            return;
        try {
            auto wire = s(settings.value(name).toString());
            if (wire.size() > 8192)
                throw std::runtime_error("Saved query exceeds size bound");
            auto j = Json::parse(wire, [](int depth, Json::parse_event_t, Json &) {
                if (depth > 8)
                    throw std::runtime_error("Saved query nesting exceeds bound");
                return true;
            });
            search_->setText(q(j.value("search", std::string{})));
            host_->setText(q(j.value("host", std::string{})));
            pid_->setText(q(j.value("pid", std::string{})));
            type_->setCurrentIndex(j.value("type", 0));
            source_->setCurrentIndex(j.value("source", 0));
            offset_ = 0;
            refresh();
        } catch (const std::exception &e) {
            QMessageBox::warning(this, "Invalid saved query", q(e.what()));
        }
    });
    connect(exportRows, &QPushButton::clicked, this, [this] {
        auto parent = QFileDialog::getExistingDirectory(this, "Choose export parent");
        if (parent.isEmpty())
            return;
        try {
            auto output = s(parent) + "/IRForge-search-" + newUuid();
            privateDirectory(output, true);
            auto base = filesystemPath(output);
            writeDocument(base / "selection.json", {{"schema_version", 1},
                                                    {"exported_at", formatUtc(utcNow())},
                                                    {"page", s(pages[navigation_->currentRow()])},
                                                    {"offset", offset_},
                                                    {"records", rows_},
                                                    {"scope", "currently displayed page only"}});
            std::ofstream csv(base / "selection.csv", std::ios::binary);
            csv << "document\r\n";
            for (const auto &row : rows_)
                csv << csvCell(row.dump()) << "\r\n";
            csv.close();
            writeDocument(base / "manifest.json", evidenceManifest(output, "saved-search"));
            summary_->setText("Exported displayed evidence: " + q(output));
        } catch (const std::exception &e) {
            summary_->setText(q(e.what()));
        }
    });
    table_ = new QTableWidget;
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setAlternatingRowColors(true);
    table_->setWordWrap(false);
    body->addWidget(table_, 1);
    auto *pagination = new QHBoxLayout;
    previous_ = new QPushButton("Previous 50");
    next_ = new QPushButton("Next 50");
    pagination->addWidget(previous_);
    pagination->addWidget(next_);
    pagination->addStretch();
    auto *details = new QPushButton("Open selected evidence");
    pagination->addWidget(details);
    body->addLayout(pagination);
    split->addWidget(content);
    split->setStretchFactor(1, 1);
    layout->addWidget(split, 1);
    setCentralWidget(root);
    connect(navigation_, &QListWidget::currentRowChanged, this, [this, pageTitle](int page) {
        if (page >= 0 && page < pages.size())
            pageTitle->setText(pages[page]);
        rows_ = Json::array();
        table_->setRowCount(0);
        offset_ = 0;
        refresh();
    });
    connect(refreshButton, &QPushButton::clicked, this, [this] {
        offset_ = 0;
        refresh();
    });
    connect(search_, &QLineEdit::returnPressed, this, [this] {
        offset_ = 0;
        refresh();
    });
    connect(previous_, &QPushButton::clicked, this, [this] {
        offset_ = std::max(0, offset_ - 50);
        refresh();
    });
    connect(next_, &QPushButton::clicked, this, [this] {
        offset_ += 50;
        refresh();
    });
    connect(table_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) { detail(row); });
    connect(details, &QPushButton::clicked, this, [this] { detail(table_->currentRow()); });
    navigation_->setCurrentRow(0);
    auto *timer = new QTimer(this);
    timer->setInterval(15000);
    connect(timer, &QTimer::timeout, this, [this] {
        if (navigation_->currentRow() == 0 || navigation_->currentRow() == 3)
            refresh();
    });
    timer->start();
}
void MainWindow::openControlPanel() {
    if (!controlPanel_) {
        controlPanel_ = new ControlPanel(pipe_, this);
        controlPanel_->setAttribute(Qt::WA_DeleteOnClose);
        connect(controlPanel_, &QObject::destroyed, this, [this] { controlPanel_ = nullptr; });
    }
    controlPanel_->show();
    controlPanel_->raise();
    controlPanel_->activateWindow();
}
void MainWindow::closeEvent(QCloseEvent *event) {
    auto *control = dynamic_cast<ControlPanel *>(controlPanel_);
    if (control && control->monitoring()) {
        QMessageBox::information(this, "Monitoring is active",
                                 "Stop the session and wait for it to finish before closing IRForge.");
        control->show();
        event->ignore();
        return;
    }
    event->accept();
}
void MainWindow::async(const std::function<Json()> &operation,
                       const std::function<void(const Json &)> &complete, int generation) {
    auto *watcher = new QFutureWatcher<Json>(this);
    connect(watcher, &QFutureWatcher<Json>::finished, this, [this, watcher, complete, generation] {
        auto result = watcher->result();
        watcher->deleteLater();
        if (generation >= 0) {
            refreshInFlight_ = false;
            if (refreshPending_) {
                refreshPending_ = false;
                QTimer::singleShot(0, this, [this] { refresh(); });
            }
            if (generation != generation_)
                return;
        }
        if (result.contains("ui_error")) {
            summary_->setText("Agent unavailable or request failed. Start a session from Monitoring setup, "
                              "then refresh. " +
                              q(result["ui_error"].get<std::string>()));
            setProperty("loaded", false);
            setProperty("request_failed", true);
            rows_.clear();
            table_->setRowCount(0);
            return;
        }
        complete(result);
    });
    watcher->setFuture(QtConcurrent::run([operation] {
        try {
            return operation();
        } catch (const std::exception &e) {
            return Json{{"ui_error", e.what()}};
        }
    }));
}
void MainWindow::selectPage(const QString &name) {
    auto items = navigation_->findItems(name, Qt::MatchExactly);
    if (!items.empty())
        navigation_->setCurrentItem(items[0]);
}
bool MainWindow::loaded() const { return property("loaded").toBool(); }
void MainWindow::refresh() {
    int page = navigation_->currentRow();
    int generation = ++generation_;
    setProperty("loaded", false);
    setProperty("request_failed", false);
    summary_->setText("Reading stored evidence from the authenticated local agent…");
    previous_->setEnabled(offset_ > 0);
    next_->setEnabled(false);
    if (refreshInFlight_) {
        refreshPending_ = true;
        return;
    }
    refreshInFlight_ = true;
    auto pipe = pipe_;
    Json filters = Json::object();
    if (!search_->text().isEmpty())
        filters["search"] = s(search_->text());
    if (!host_->text().isEmpty() && page != 6 && page != 8 && page != 9 && page != 7 && page != 10)
        filters["host"] = s(host_->text());
    if (page == 1) {
        if (severity_->currentIndex() > 0)
            filters["severity"] = s(severity_->currentText());
        if (state_->currentIndex() > 0)
            filters["status"] = s(state_->currentText());
    }
    if ((page == 3 || page == 4 || page == 11 || page == 12) && !pid_->text().isEmpty())
        filters["pid"] = s(pid_->text());
    if (page == 3 || page == 11 || page == 12) {
        if (type_->currentIndex() > 0)
            filters["type"] = s(type_->currentText());
        if (source_->currentIndex() > 0)
            filters["source"] = s(source_->currentText());
    }
    if (page == 12) {
        filters.erase("type");
        filters["types"] =
            Json::array({"tcp_connection_observed", "tcp_connection_closed", "sysmon_network_connect"});
    }
    if (page == 4)
        filters["types"] = Json::array(
            {"registry_value_added", "registry_value_modified", "registry_value_deleted",
             "registry_key_added", "registry_key_deleted", "scheduled_task_added", "scheduled_task_changed",
             "scheduled_task_removed", "service_created", "service_changed", "service_removed",
             "startup_entry_added", "startup_entry_changed", "startup_entry_removed"});
    const std::map<int, std::string> tables = {{1, "incidents"}, {2, "processes"},    {3, "events"},
                                               {4, "events"},    {5, "artifacts"},    {7, "hosts"},
                                               {8, "ti_cache"},  {9, "config_audit"}, {10, "baselines"},
                                               {11, "events"},   {12, "events"}};
    Json request = page == 0   ? Json{{"op", "health"}}
                   : page == 6 ? Json{{"op", "rules"}}
                               : Json{{"op", "query"},
                                      {"table", tables.at(page)},
                                      {"filters", filters},
                                      {"limit", 50},
                                      {"offset", offset_}};
    async(
        [pipe, request, page] {
            constexpr int timeout = 5000, connectTimeout = 1000;
            auto result = pipeRequest(pipe, request, timeout, connectTimeout);
            if (page == 0) {
                Json counts = Json::object();
                for (const auto *table : {"events", "incidents", "processes", "artifacts"})
                    counts[table] = result.value(table, 0);
                result["counts"] = counts;
                result["sessions"] =
                    pipeRequest(pipe, {{"op", "query"}, {"table", "sessions"}, {"limit", 10}}, timeout,
                                connectTimeout)["rows"];
            }
            if (page == 7)
                result["cases"] = pipeRequest(pipe, {{"op", "query"}, {"table", "cases"}, {"limit", 50}},
                                              timeout, connectTimeout)["rows"];
            if (page == 9)
                result["health"] = pipeRequest(pipe, {{"op", "health"}}, timeout, connectTimeout);
            if (page == 9)
                result["jobs"] = pipeRequest(pipe,
                                             {{"op", "query"},
                                              {"table", "health"},
                                              {"filters", {{"search", "job_id"}}},
                                              {"limit", 50}},
                                             timeout, connectTimeout)["rows"];
            return result;
        },
        [this, generation, page](const Json &result) {
            if (generation != generation_)
                return;
            rows_ = Json::array();
            std::vector<std::pair<QString, std::string>> columns;
            if (page == 0) {
                administrator_ = result.value("principal", Json::object()).value("administrator", false);
                for (auto it = result.begin(); it != result.end(); ++it)
                    rows_.push_back({{"section", it.key()}, {"data", it.value()}});
                columns = {{"Evidence section", "section"}, {"Recorded value", "data"}};
                summary_->setText(
                    "Stored evidence totals: " + q(result["counts"].dump()) +
                    ". Current reader: " + (administrator_ ? "elevated administrator" : "read-only user") +
                    ". Session mode identifies replay versus live recording.");
            } else {
                rows_ = result.at("rows");
                if (page == 9 && result.contains("health"))
                    rows_.push_back({{"operation", "agent_health"},
                                     {"author", "authenticated local agent"},
                                     {"data", result["health"]}});
                if (page == 9)
                    for (const auto &job : result["jobs"])
                        rows_.push_back({{"operation", "manual_TI_result"},
                                         {"author", job.value("author", std::string("operator"))},
                                         {"data", job}});
                if (page == 1)
                    for (const auto &row : rows_)
                        if (row.value("host_id", std::string{}) == "replay")
                            summary_->setText("OFFLINE REPLAY — synthetic fixture results; these scores do "
                                              "not describe this Windows host.");
                if (page == 7)
                    for (const auto &c : result["cases"])
                        rows_.push_back(c);
                summary_->setText(QString("%1 — %2 stored rows, page starting at %3. Double-click to inspect "
                                          "original fields and provenance.")
                                      .arg(pages[page])
                                      .arg(result.value("total", 0))
                                      .arg(offset_));
                next_->setEnabled(result.value("has_more", false));
            }
            if (page == 1)
                columns = {{"Severity", "severity"},
                           {"Score", "risk_score"},
                           {"Confidence", "confidence"},
                           {"State", "status"},
                           {"Last updated", "last_updated_at"},
                           {"Incident ID", "incident_id"}};
            if (page == 2)
                columns = {{"PID", "payload.identity.pid"},
                           {"Image", "payload.image_path"},
                           {"Command line", "payload.command_line"},
                           {"Parent PID", "payload.parent_pid"},
                           {"GUID", "payload.identity.sysmon_process_guid"},
                           {"Observed", "timestamp_utc"}};
            if (page == 3 || page == 4 || page == 11 || page == 12)
                columns = {{"Timestamp", "timestamp_utc"},
                           {"Type", "event_type"},
                           {"Source", "source"},
                           {"Attribution", "attribution.method"},
                           {"Confidence", "attribution.confidence"},
                           {"Payload", "payload"}};
            if (page == 5)
                columns = {{"Path", "payload.path"},
                           {"SHA-256", "payload.metadata.hash.sha256"},
                           {"Hash status", "payload.metadata.hash.status"},
                           {"Signature", "payload.metadata.signature.status"},
                           {"Signer", "payload.metadata.signature.signer"},
                           {"YARA", "payload.metadata.yara.matches"}};
            if (page == 6)
                columns = {{"ID", "id"},
                           {"Name", "name"},
                           {"Enabled", "enabled"},
                           {"Points", "points"},
                           {"Mapped ATT&CK", "attack"},
                           {"Description", "description"}};
            if (page == 7)
                columns = {{"Host / case", "name"},
                           {"ID", "host_id"},
                           {"Details", "title"},
                           {"Mode", "mode"},
                           {"Document", "summary"}};
            if (page == 8)
                columns = {{"Indicator", "indicator"},  {"Provider", "provider"},  {"Verdict", "verdict"},
                           {"Looked up", "fetched_at"}, {"Expires", "expires_at"}, {"Details", "response"}};
            if (page == 9)
                columns = {{"Operation", "operation"}, {"Author", "author"}, {"Details", "data"}};
            if (page == 10)
                columns = {{"Host", "host_id"},
                           {"State", "mode"},
                           {"Samples", "samples"},
                           {"Last learned", "updated_at"},
                           {"Coverage", "features"}};
            table_->setSortingEnabled(false);
            table_->clear();
            table_->setColumnCount(static_cast<int>(columns.size()));
            table_->setRowCount(static_cast<int>(rows_.size()));
            QStringList headers;
            for (const auto &c : columns)
                headers << c.first;
            table_->setHorizontalHeaderLabels(headers);
            for (std::size_t i = 0; i < rows_.size(); ++i)
                for (std::size_t c = 0; c < columns.size(); ++c) {
                    auto text = value(rows_[i], columns[c].second);
                    if (localTime_ && columns[c].second.ends_with("_utc")) {
                        auto time = QDateTime::fromString(text, Qt::ISODateWithMs);
                        if (time.isValid())
                            text = time.toLocalTime().toString(Qt::ISODateWithMs);
                    }
                    auto *item = new QTableWidgetItem(text.left(1000));
                    item->setData(Qt::UserRole, static_cast<int>(i));
                    item->setToolTip(text.left(16384));
                    table_->setItem(static_cast<int>(i), static_cast<int>(c), item);
                }
            table_->setSortingEnabled(true);
            table_->resizeColumnsToContents();
            for (int c = 0; c < table_->columnCount(); ++c)
                if (table_->columnWidth(c) > 420)
                    table_->setColumnWidth(c, 420);
            setProperty("loaded", true);
            if (page == 1 || page == 3 || page == 11 || page == 12)
                for (const auto &row : rows_)
                    if (row.value("acquisition_mode", std::string{}) == "replay" ||
                        row.value("host_id", std::string{}) == "replay")
                        summary_->setText("OFFLINE REPLAY — synthetic fixture results; these scores do not "
                                          "describe this Windows host.");
        },
        generation);
}
void MainWindow::detail(int row) {
    if (row >= 0 && table_->item(row, 0))
        row = table_->item(row, 0)->data(Qt::UserRole).toInt();
    if (row < 0 || row >= static_cast<int>(rows_.size()))
        return;
    auto data = rows_[row];
    if (navigation_->currentRow() == 1) {
        auto pipe = pipe_;
        auto id = data.at("incident_id").get<std::string>();
        async([pipe, id] { return pipeRequest(pipe, {{"op", "detail"}, {"id", id}}); },
              [this](const Json &result) { showIncident(result); });
        return;
    }
    QDialog dialog(this);
    dialog.setWindowTitle("Stored evidence and provenance");
    dialog.resize(1000, 740);
    QVBoxLayout layout(&dialog);
    auto *text = document(data);
    layout.addWidget(text);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout.addWidget(buttons);
    if (navigation_->currentRow() == 10 || (navigation_->currentRow() == 7 && data.contains("host_id"))) {
        auto *baselineButtons = new QHBoxLayout;
        for (const auto &action : {std::string("learn"), std::string("freeze"), std::string("reset")}) {
            auto *button = new QPushButton(q(action + " baseline"));
            baselineButtons->addWidget(button);
            connect(button, &QPushButton::clicked, &dialog, [this, data, action] {
                if (action == "reset" &&
                    QMessageBox::question(this, "Reset baseline",
                                          "Remove IRForge's learned reference for this host?") !=
                        QMessageBox::Yes)
                    return;
                mutate({{"op", "baseline_change"},
                        {"host", data.at("host_id")},
                        {"action", action},
                        {"opt_in", true},
                        {"confirm", action == "reset"}},
                       [this](const Json &) { refresh(); });
            });
        }
        layout.addLayout(baselineButtons);
        auto *showBaseline = new QPushButton("Inspect baseline and deviation history");
        layout.addWidget(showBaseline);
        connect(showBaseline, &QPushButton::clicked, &dialog, [this, data] {
            auto pipe = pipe_;
            auto host = data.at("host_id");
            async(
                [pipe, host] {
                    auto result = pipeRequest(pipe, {{"op", "baseline"}, {"host", host}});
                    result["recent_deviations"] =
                        pipeRequest(pipe, {{"op", "query"},
                                           {"table", "events"},
                                           {"filters", {{"host", host}, {"type", "baseline_deviation"}}},
                                           {"limit", 50}})["rows"];
                    return result;
                },
                [this](const Json &j) {
                    QDialog view(this);
                    QVBoxLayout body(&view);
                    body.addWidget(document(j));
                    view.resize(900, 650);
                    view.exec();
                });
        });
    }
    if (navigation_->currentRow() == 6) {
        auto *toggle = new QPushButton(data.value("enabled", true) ? "Disable rule (administrator)"
                                                                   : "Enable rule (administrator)");
        layout.addWidget(toggle);
        connect(toggle, &QPushButton::clicked, &dialog, [this, data, &dialog] {
            auto id = data.at("id").get<std::string>();
            mutate({{"op", "rule_toggle"}, {"id", id}, {"enabled", !data.value("enabled", true)}},
                   [this, guard = QPointer<QDialog>(&dialog)](const Json &) {
                       if (guard)
                           guard->accept();
                       refresh();
                   });
        });
    }
    if (navigation_->currentRow() == 1 || data.contains("incident_id")) {
        auto *caseButton = new QPushButton("Create case from this incident");
        caseButton->setEnabled(administrator_);
        layout.addWidget(caseButton);
        connect(caseButton, &QPushButton::clicked, &dialog, [this, data, &dialog] {
            bool ok = false;
            auto title = QInputDialog::getText(&dialog, "Create audited case", "Case title",
                                               QLineEdit::Normal, "", &ok);
            if (!ok || title.trimmed().isEmpty())
                return;
            auto pipe = pipe_;
            auto request = Json{{"op", "case_create"},
                                {"title", s(title)},
                                {"incident_ids", Json::array({data.at("incident_id")})}};
            async([pipe, request] { return pipeRequest(pipe, request); },
                  [this](const Json &result) {
                      summary_->setText("Created case " + q(result.at("case_id").get<std::string>()));
                  });
        });
    }
    dialog.exec();
}
void MainWindow::openIncident(const std::string &id) {
    setProperty("loaded", false);
    auto pipe = pipe_;
    async([pipe, id] { return pipeRequest(pipe, {{"op", "detail"}, {"id", id}}); },
          [this](const Json &data) {
              setProperty("incident_ready", true);
              showIncident(data);
          });
}
void MainWindow::showIncident(const Json &incident) {
    QDialog dialog(this);
    dialog.setWindowTitle("Incident — " + q(incident.at("incident_id").get<std::string>()));
    dialog.resize(1160, 820);
    QVBoxLayout layout(&dialog);
    auto *title = new QLabel(QString("Score %1 / %2 | confidence %3 | analyst state %4 | revision %5")
                                 .arg(incident.at("risk_score").get<int>())
                                 .arg(value(incident, "severity"), value(incident, "confidence"),
                                      value(incident, "status"), value(incident, "revision")));
    title->setTextFormat(Qt::PlainText);
    layout.addWidget(title);
    auto *tabs = new QTabWidget;
    tabs->addTab(document(incident.at("timeline")), "Timeline / provenance");
    tabs->addTab(document(incident.at("rule_matches")), "Rule explanations");
    tabs->addTab(document(incident.at("attack_techniques")), "Mapped ATT&CK");
    tabs->addTab(document(incident.at("analyst_annotations")), "Annotations / audit");
    tabs->addTab(document(incident.value("coverage_gaps", Json::array())), "Coverage gaps");
    auto *scene = new QGraphicsScene(tabs);
    auto *graph = new QGraphicsView(scene);
    std::map<std::string, QPointF> positions;
    auto g = incident.value("graph", Json{{"nodes", Json::array()}, {"edges", Json::array()}});
    int index = 0;
    for (const auto &node : g["nodes"]) {
        QPointF pos((index % 4) * 250, (index / 4) * 130);
        positions[node["id"].get<std::string>()] = pos;
        auto *box =
            scene->addRect(QRectF(pos, QSizeF(220, 80)), QPen(QColor("#147b86")), QBrush(QColor("#edf6f6")));
        box->setToolTip(q(node.dump(2)));
        auto *label = scene->addText(
            q(node["kind"].get<std::string>() + "\n" + node["label"].get<std::string>()).left(100));
        label->setPos(pos + QPointF(8, 8));
        label->setTextWidth(205);
        ++index;
    }
    for (const auto &edge : g["edges"]) {
        auto from = edge["from"].get<std::string>(), to = edge["to"].get<std::string>();
        if (!positions.contains(from) || !positions.contains(to))
            continue;
        auto line = QLineF(positions[from] + QPointF(110, 80), positions[to] + QPointF(110, 0));
        auto *item = scene->addLine(
            line, QPen(edge["confidence"] == "high" ? QColor("#147b86") : QColor("#c08028"), 2));
        item->setToolTip(q(edge.dump(2)));
        auto *label = scene->addText(
            q(edge["type"].get<std::string>() + " / " + edge["confidence"].get<std::string>()));
        label->setPos(line.center());
    }
    tabs->addTab(graph, "Evidence graph");
    layout.addWidget(tabs, 1);
    auto *actions = new QHBoxLayout;
    auto *exportButton = new QPushButton("Export HTML / PDF / JSON / CSV / STIX");
    actions->addWidget(exportButton);
    auto *state = new QComboBox;
    state->addItems({"new", "investigating", "benign", "resolved"});
    state->setCurrentText(value(incident, "status"));
    auto *note = new QLineEdit;
    note->setPlaceholderText("Analyst note (audited)");
    auto *save = new QPushButton("Save state and note");
    actions->addWidget(state);
    actions->addWidget(note, 1);
    actions->addWidget(save);
    layout.addLayout(actions);
    connect(save, &QPushButton::clicked, &dialog, [this, incident, state, note, &dialog] {
        auto request = Json{{"op", "annotate"},
                            {"id", incident.at("incident_id")},
                            {"text", s(note->text())},
                            {"state", s(state->currentText())}};
        mutate(request, [this, guard = QPointer<QDialog>(&dialog)](const Json &) {
            if (guard)
                guard->accept();
            refresh();
        });
    });
    auto *caseButton = new QPushButton("Create case");
    actions->addWidget(caseButton);
    connect(caseButton, &QPushButton::clicked, &dialog, [this, incident, &dialog] {
        bool ok = false;
        auto title =
            QInputDialog::getText(&dialog, "Create audited case", "Case title", QLineEdit::Normal, "", &ok);
        if (!ok || title.trimmed().isEmpty())
            return;
        mutate(
            {{"op", "case_create"},
             {"title", s(title)},
             {"incident_ids", Json::array({incident.at("incident_id")})}},
            [this](const Json &) { summary_->setText("Case saved; open Hosts and Cases to inspect it."); });
    });
    connect(exportButton, &QPushButton::clicked, &dialog, [this, incident, &dialog] {
        auto directory =
            QFileDialog::getExistingDirectory(&dialog, "Choose parent folder for a new evidence export");
        if (directory.isEmpty())
            return;
        try {
            auto output = s(directory) + "/IRForge-report-" + newUuid();
            privateDirectory(output, true);
            auto base = filesystemPath(output);
            Json context = {{"exported_at", formatUtc(utcNow())},
                            {"incident_revision", incident.at("revision")},
                            {"source", "authenticated local agent"}};
            writeDocument(base / "incident.json", incident);
            writeDocument(base / "export-context.json", context);
            auto html = incidentHtml(incident, context);
            {
                std::ofstream file(base / "report.html", std::ios::binary);
                file << html;
                if (!file)
                    throw std::runtime_error("HTML report write failed");
            }
            QTextDocument doc;
            doc.setHtml(q(html));
            {
                QPdfWriter pdf(q((base / "report.pdf").string()));
                pdf.setResolution(96);
                pdf.setPageSize(QPageSize(QPageSize::A4));
                pdf.setTitle("IRForge incident evidence report");
                pdf.setCreator("IRForge 1.0.0-dev");
                doc.print(&pdf);
            }
            if (!std::filesystem::exists(base / "report.pdf") ||
                std::filesystem::file_size(base / "report.pdf") == 0)
                throw std::runtime_error("PDF write failed");
            try {
                writeDocument(base / "observations.stix.json", stixBundle(incident));
            } catch (const std::exception &e) {
                writeDocument(base / "stix-not-exported.json", {{"reason", e.what()}});
            }
            std::ofstream csv(base / "events.csv", std::ios::binary);
            csv << "event_id,timestamp_utc,event_type,source,payload\r\n";
            for (const auto &e : incident["timeline"])
                csv << csvCell(e.at("event_id").get<std::string>()) << ','
                    << csvCell(e.at("timestamp_utc").get<std::string>()) << ','
                    << csvCell(e.at("event_type").get<std::string>()) << ','
                    << csvCell(e.at("source").get<std::string>()) << ',' << csvCell(e.at("payload").dump())
                    << "\r\n";
            csv.close();
            if (!csv)
                throw std::runtime_error("CSV write failed");
            writeDocument(base / "manifest.json", evidenceManifest(output, incident.at("incident_id")));
            QMessageBox::information(&dialog, "Evidence export complete", q(output));
        } catch (const std::exception &e) {
            QMessageBox::critical(&dialog, "Export failed", q(e.what()));
        }
    });
    auto *close = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(close, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout.addWidget(close);
    dialog.exec();
}
} // namespace irforge
