#include "ControlPanel.hpp"
#include "irforge/core/Config.hpp"
#include "irforge/core/Event.hpp"
#include "irforge/core/Schema.hpp"
#include <QCheckBox>
#include <QCloseEvent>
#include <QCoreApplication>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPushButton>
#include <QSaveFile>
#include <QSpinBox>
#include <QStandardPaths>
#include <QTabWidget>
#include <QTemporaryFile>
#include <QUrl>
#include <QVBoxLayout>
#include <windows.h>

namespace irforge {
namespace {
std::string bytes(const QString &value) { return value.toUtf8().toStdString(); }
QString str(const std::string &value) {
    return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
}
QString projectRoot() {
    QDir dir(QCoreApplication::applicationDirPath());
    for (int i = 0; i < 5; ++i) {
        if (dir.exists("config/default.json") && dir.exists("rules/internal"))
            return dir.absolutePath();
        if (!dir.cdUp())
            break;
    }
    return QCoreApplication::applicationDirPath();
}
} // namespace
ControlPanel::ControlPanel(std::string pipe, QWidget *parent) : QDialog(parent), pipe_(std::move(pipe)) {
    setObjectName("monitoringControlPanel");
    setWindowTitle("IRForge — Monitoring setup");
    setModal(false);
    resize(860, 760);
    auto *layout = new QVBoxLayout(this);
    auto *intro = new QLabel(
        "Configure collection, start a local session, then review the evidence in the main window.");
    intro->setWordWrap(true);
    layout->addWidget(intro);
    auto *paths = new QFormLayout;
    auto pathRow = [this, paths](const QString &label, QLineEdit *&edit, const QString &initial,
                                 bool directory) {
        auto *row = new QWidget;
        auto *horizontal = new QHBoxLayout(row);
        horizontal->setContentsMargins(0, 0, 0, 0);
        edit = new QLineEdit(initial);
        auto *browse = new QPushButton("Browse…");
        horizontal->addWidget(edit, 1);
        horizontal->addWidget(browse);
        connect(browse, &QPushButton::clicked, this, [this, edit, directory] {
            auto selected = directory ? QFileDialog::getExistingDirectory(this, "Choose folder", edit->text())
                                      : QFileDialog::getOpenFileName(this, "Choose configuration",
                                                                     edit->text(), "JSON (*.json)");
            if (!selected.isEmpty())
                edit->setText(selected);
        });
        paths->addRow(label, row);
    };
    const auto root = projectRoot();
    pathRow("Configuration file", configPath_, root + "/config/default.json", false);
    pathRow("Detection rules", rulesPath_, root + "/rules/internal", true);
    auto output = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + "/IRForge";
    pathRow("Results folder", outputPath_, output, true);
    layout->addLayout(paths);
    auto *load = new QPushButton("Load configuration");
    layout->addWidget(load);
    connect(load, &QPushButton::clicked, this, [this] { loadConfig(); });

    auto *tabs = new QTabWidget;
    auto *basic = new QWidget;
    auto *form = new QFormLayout(basic);
    auto flag = [form](const QString &label, QCheckBox *&box) {
        box = new QCheckBox;
        form->addRow(label, box);
    };
    flag("Process starts and stops (ETW)", processEvents_);
    flag("TCP connection observations", network_);
    flag("Registry Run keys and services", registry_);
    flag("Capture command lines", commands_);
    flag("Watch selected folders", file_);
    roots_ = new QLineEdit;
    roots_->setPlaceholderText("One or more folder paths, separated by semicolons");
    auto *rootsRow = new QWidget;
    auto *rootsLayout = new QHBoxLayout(rootsRow);
    rootsLayout->setContentsMargins(0, 0, 0, 0);
    auto *addRoot = new QPushButton("Add folder…");
    rootsLayout->addWidget(roots_, 1);
    rootsLayout->addWidget(addRoot);
    form->addRow("Watched folders", rootsRow);
    connect(addRoot, &QPushButton::clicked, this, [this] {
        auto folder = QFileDialog::getExistingDirectory(this, "Choose a folder to watch");
        if (!folder.isEmpty())
            roots_->setText(roots_->text().isEmpty() ? folder : roots_->text() + "; " + folder);
    });
    flag("Persistence inventory", inventory_);
    flag("Windows Event Log / Sysmon", eventLog_);
    flag("Local YARA rules", yara_);
    auto *explain = new QLabel("Folder and YARA collection are opt-in. Changes apply to the next session. "
                               "Use Advanced JSON for every supported setting.");
    explain->setWordWrap(true);
    form->addRow(explain);
    tabs->addTab(basic, "Collection");
    auto *advanced = new QWidget;
    auto *advancedLayout = new QVBoxLayout(advanced);
    auto *hint =
        new QLabel("Complete configuration (JSON). Edit this directly for retention, privacy, enrichment, "
                   "remote and other advanced options. Validate and save before starting.");
    hint->setWordWrap(true);
    advancedLayout->addWidget(hint);
    editor_ = new QPlainTextEdit;
    advancedLayout->addWidget(editor_);
    tabs->addTab(advanced, "Advanced JSON");
    layout->addWidget(tabs, 1);
    connect(tabs, &QTabWidget::currentChanged, this, [this](int index) {
        try {
            if (index == 0)
                populate();
            else
                applyFields();
        } catch (const std::exception &e) {
            QMessageBox::warning(this, "Invalid configuration", str(e.what()));
        }
    });
    auto *save = new QPushButton("Validate and save configuration as…");
    layout->addWidget(save);
    connect(save, &QPushButton::clicked, this, [this, tabs] {
        if (tabs->currentIndex() == 0) {
            try {
                applyFields();
            } catch (const std::exception &e) {
                QMessageBox::warning(this, "Invalid configuration", str(e.what()));
                return;
            }
        }
        saveConfig();
    });
    auto *actions = new QHBoxLayout;
    duration_ = new QSpinBox;
    duration_->setRange(1, 1440);
    duration_->setValue(5);
    duration_->setSuffix(" min");
    start_ = new QPushButton("Start monitoring");
    stop_ = new QPushButton("Stop session");
    openRecording_ = new QPushButton("Open saved recording…");
    stop_->setEnabled(false);
    actions->addWidget(new QLabel("Duration"));
    actions->addWidget(duration_);
    actions->addStretch();
    actions->addWidget(openRecording_);
    actions->addWidget(start_);
    actions->addWidget(stop_);
    layout->addLayout(actions);
    status_ = new QLabel("Ready. ETW may require launching the GUI as administrator.");
    status_->setWordWrap(true);
    layout->addWidget(status_);
    auto *openResults = new QPushButton("Open results folder");
    layout->addWidget(openResults);
    connect(openResults, &QPushButton::clicked, this, [this] {
        auto folder = sessionPath_.isEmpty() ? outputPath_->text() : sessionPath_;
        if (QFileInfo(folder).isFile())
            folder = QFileInfo(folder).absolutePath();
        if (!QDir(folder).exists() || !QDesktopServices::openUrl(QUrl::fromLocalFile(folder)))
            QMessageBox::warning(this, "Cannot open results", "The results folder is not available yet.");
    });
    log_ = new QPlainTextEdit;
    log_->setReadOnly(true);
    log_->setMaximumHeight(110);
    log_->setPlaceholderText("Monitor output and errors appear here.");
    log_->document()->setMaximumBlockCount(500);
    layout->addWidget(log_);
    process_ = new QProcess(this);
    process_->setProcessChannelMode(QProcess::MergedChannels);
    connect(process_, &QProcess::readyReadStandardOutput, this, [this] {
        log_->appendPlainText(QString::fromLocal8Bit(process_->readAllStandardOutput()).trimmed());
    });
    connect(process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        status_->setText("Monitor error: " + process_->errorString());
        if (error == QProcess::FailedToStart) {
            if (stopEvent_) {
                CloseHandle(static_cast<HANDLE>(stopEvent_));
                stopEvent_ = nullptr;
            }
            start_->setEnabled(true);
            openRecording_->setEnabled(true);
            stop_->setEnabled(false);
        }
    });
    connect(process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this](int code, QProcess::ExitStatus result) {
                if (stopEvent_) {
                    CloseHandle(static_cast<HANDLE>(stopEvent_));
                    stopEvent_ = nullptr;
                }
                start_->setEnabled(true);
                openRecording_->setEnabled(true);
                stop_->setEnabled(false);
                status_->setText((result == QProcess::NormalExit && code == 0
                                      ? "Session finished. Results: "
                                      : "Monitor failed or exited with code " + QString::number(code) +
                                            ". Inspect the log. Results: ") +
                                 sessionPath_);
            });
    connect(start_, &QPushButton::clicked, this, [this, tabs] {
        if (tabs->currentIndex() == 0) {
            try {
                applyFields();
            } catch (const std::exception &e) {
                QMessageBox::warning(this, "Invalid configuration", str(e.what()));
                return;
            }
        }
        startMonitor();
    });
    connect(stop_, &QPushButton::clicked, this, [this] { stopMonitor(); });
    connect(openRecording_, &QPushButton::clicked, this, [this] { openRecording(); });
    loadConfig();
}
void ControlPanel::loadConfig() {
    QFile file(configPath_->text());
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "Cannot open configuration", file.errorString());
        return;
    }
    editor_->setPlainText(QString::fromUtf8(file.readAll()));
    try {
        populate();
        status_->setText("Configuration loaded. Save a copy before starting.");
    } catch (const std::exception &e) {
        QMessageBox::warning(this, "Invalid configuration", str(e.what()));
    }
}
void ControlPanel::populate() {
    auto j = Json::parse(bytes(editor_->toPlainText()));
    processEvents_->setChecked(j.value("process_etw_enabled", true));
    network_->setChecked(j.value("network_enabled", true));
    registry_->setChecked(j.value("registry_enabled", true));
    commands_->setChecked(j.value("capture_command_line", true));
    auto file = j.value("file_monitor", Json::object());
    file_->setChecked(file.value("enabled", false));
    QStringList roots;
    for (const auto &root : file.value("roots", std::vector<std::string>{}))
        roots << str(root);
    roots_->setText(roots.join("; "));
    inventory_->setChecked(j.value("inventory", Json::object()).value("enabled", false));
    eventLog_->setChecked(j.value("windows_eventlog", Json::object()).value("enabled", false));
    yara_->setChecked(j.value("yara", Json::object()).value("enabled", false));
}
void ControlPanel::applyFields() {
    auto j = Json::parse(bytes(editor_->toPlainText()));
    j["process_etw_enabled"] = processEvents_->isChecked();
    j["network_enabled"] = network_->isChecked();
    j["registry_enabled"] = registry_->isChecked();
    j["capture_command_line"] = commands_->isChecked();
    j["file_monitor"]["enabled"] = file_->isChecked();
    std::vector<std::string> roots;
    for (const auto &root : roots_->text().split(';', Qt::SkipEmptyParts))
        if (!root.trimmed().isEmpty())
            roots.push_back(bytes(root.trimmed()));
    j["file_monitor"]["roots"] = roots;
    j["inventory"]["enabled"] = inventory_->isChecked();
    j["windows_eventlog"]["enabled"] = eventLog_->isChecked();
    j["yara"]["enabled"] = yara_->isChecked();
    editor_->setPlainText(str(j.dump(2)));
}
bool ControlPanel::saveConfig() {
    try {
        QTemporaryFile candidate;
        if (!candidate.open())
            throw std::runtime_error("Cannot create temporary validation file");
        const auto data = editor_->toPlainText().toUtf8();
        if (candidate.write(data) != data.size() || !candidate.flush())
            throw std::runtime_error("Cannot write validation file");
        Config::load(bytes(candidate.fileName()));
        auto configHome = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
        QDir().mkpath(configHome);
        auto suggested = configPath_->text() == projectRoot() + "/config/default.json"
                             ? configHome + "/monitor-config.json"
                             : configPath_->text();
        auto name = QFileDialog::getSaveFileName(this, "Save configuration", suggested, "JSON (*.json)");
        if (name.isEmpty())
            return false;
        QSaveFile out(name);
        if (!out.open(QIODevice::WriteOnly) || out.write(data) != data.size() || !out.commit())
            throw std::runtime_error("Cannot save configuration");
        configPath_->setText(name);
        status_->setText("Configuration validated and saved: " + name);
        return true;
    } catch (const std::exception &e) {
        QMessageBox::warning(this, "Configuration not saved", str(e.what()));
        return false;
    }
}
void ControlPanel::startMonitor() {
    if (process_->state() != QProcess::NotRunning)
        return;
    if (!saveConfig())
        return;
    const auto exe = QCoreApplication::applicationDirPath() + "/irforge.exe";
    if (!QFileInfo::exists(exe) || !QDir(rulesPath_->text()).exists()) {
        QMessageBox::warning(this, "Cannot start", "irforge.exe or the selected rules folder was not found.");
        return;
    }
    if (!QDir().mkpath(outputPath_->text())) {
        QMessageBox::warning(this, "Cannot start", "Cannot create the results folder.");
        return;
    }
    sessionPath_ = QDir(outputPath_->text()).filePath("session-" + str(newUuid()));
    const auto eventName = QStringLiteral("Local\\IRForge.Stop.") + str(newUuid());
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, reinterpret_cast<LPCWSTR>(eventName.utf16()));
    if (!stopEvent_) {
        QMessageBox::warning(this, "Cannot start", "Cannot create the session stop signal.");
        return;
    }
    auto env = QProcessEnvironment::systemEnvironment();
    env.insert("IRFORGE_STOP_EVENT", eventName);
    process_->setProcessEnvironment(env);
    process_->setWorkingDirectory(projectRoot());
    process_->start(exe, {"monitor", "--config", configPath_->text(), "--rules", rulesPath_->text(),
                          "--output", sessionPath_, "--pipe", str(pipe_), "--duration-seconds",
                          QString::number(duration_->value() * 60), "--allow-degraded"});
    start_->setEnabled(false);
    openRecording_->setEnabled(false);
    stop_->setEnabled(true);
    status_->setText("Starting monitor. Results: " + sessionPath_ +
                     ". Check Settings and Health for source coverage.");
}
void ControlPanel::openRecording() {
    if (process_->state() != QProcess::NotRunning)
        return;
    auto db = QFileDialog::getOpenFileName(this, "Open a saved IRForge recording", outputPath_->text(),
                                           "SQLite database (*.sqlite *.db)");
    if (db.isEmpty())
        return;
    const auto exe = QCoreApplication::applicationDirPath() + "/irforge.exe";
    if (!QFileInfo::exists(exe) || !QDir(rulesPath_->text()).exists()) {
        QMessageBox::warning(this, "Cannot open recording",
                             "irforge.exe or the selected rules folder was not found.");
        return;
    }
    sessionPath_ = db;
    const auto eventName = QStringLiteral("Local\\IRForge.Stop.") + str(newUuid());
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, reinterpret_cast<LPCWSTR>(eventName.utf16()));
    if (!stopEvent_) {
        QMessageBox::warning(this, "Cannot open recording", "Cannot create the stop signal.");
        return;
    }
    auto env = QProcessEnvironment::systemEnvironment();
    env.insert("IRFORGE_STOP_EVENT", eventName);
    process_->setProcessEnvironment(env);
    process_->setWorkingDirectory(projectRoot());
    process_->start(exe, {"agent", "serve", "--db", db, "--rules", rulesPath_->text(), "--pipe", str(pipe_),
                          "--duration-seconds", QString::number(duration_->value() * 60)});
    start_->setEnabled(false);
    openRecording_->setEnabled(false);
    stop_->setEnabled(true);
    status_->setText("Opening saved recording: " + db + ". Refresh the main window to review it.");
}
void ControlPanel::stopMonitor() {
    if (stopEvent_) {
        SetEvent(static_cast<HANDLE>(stopEvent_));
        stop_->setEnabled(false);
        status_->setText("Stopping and writing session results…");
    }
}
bool ControlPanel::monitoring() const { return process_->state() != QProcess::NotRunning; }
void ControlPanel::closeEvent(QCloseEvent *event) {
    if (process_->state() != QProcess::NotRunning) {
        hide();
        event->ignore();
        status_->setText("The session continues. Reopen this panel to stop it.");
        return;
    }
    event->accept();
}
} // namespace irforge
