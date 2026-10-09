#include "MainWindow.hpp"
#include "irforge/ipc/PipeServer.hpp"
#include "irforge/reporting/Evidence.hpp"
#include "irforge/reporting/ReportExporter.hpp"
#include <QApplication>
#include <QCheckBox>
#include <QElapsedTimer>
#include <QPalette>
#include <QPdfWriter>
#include <QTextDocument>
#include <QThreadPool>
#include <QTimer>
#include <fstream>
int main(int argc, char **argv) {
    QApplication app(argc, argv);
    QApplication::setStyle("Fusion");
    QPalette palette;
    palette.setColor(QPalette::Window, QColor("#f4f8fa"));
    palette.setColor(QPalette::WindowText, QColor("#183044"));
    palette.setColor(QPalette::Base, Qt::white);
    palette.setColor(QPalette::AlternateBase, QColor("#edf4f6"));
    palette.setColor(QPalette::Text, QColor("#183044"));
    palette.setColor(QPalette::Button, QColor("#e3f0f2"));
    palette.setColor(QPalette::ButtonText, QColor("#183044"));
    palette.setColor(QPalette::Highlight, QColor("#147b86"));
    palette.setColor(QPalette::HighlightedText, Qt::white);
    app.setPalette(palette);
    QThreadPool::globalInstance()->setMaxThreadCount(4);
    QStringList args = app.arguments();
    auto option = [&](const QString &key, const QString &fallback) {
        auto at = args.indexOf(key);
        return at >= 0 && at + 1 < args.size() ? args[at + 1] : fallback;
    };
    auto pipe = option("--pipe", "IRForge.Agent.v1").toStdString();
    if (args.contains("--export-pdf"))
        try {
            auto id = option("--incident", "").toStdString();
            auto output = option("--output", "").toStdString();
            if (id.empty() || output.empty())
                throw std::runtime_error("PDF export requires --incident and --output");
            auto incident = irforge::pipeRequest(pipe, {{"op", "detail"}, {"id", id}});
            irforge::privateDirectory(output, true);
            auto base = irforge::filesystemPath(output);
            irforge::Json context = {{"exported_at", irforge::formatUtc(irforge::utcNow())},
                                     {"incident_revision", incident.at("revision")},
                                     {"source", "authenticated local agent"}};
            irforge::writeDocument(base / "incident.json", incident);
            irforge::writeDocument(base / "export-context.json", context);
            QTextDocument document;
            document.setHtml(QString::fromUtf8(irforge::incidentHtml(incident, context)));
            {
                QPdfWriter pdf(QString::fromStdString((base / "report.pdf").string()));
                pdf.setResolution(96);
                pdf.setPageSize(QPageSize(QPageSize::A4));
                pdf.setTitle("IRForge incident evidence report");
                document.print(&pdf);
            }
            irforge::writeDocument(base / "manifest.json", irforge::evidenceManifest(output, id));
            return std::filesystem::file_size(base / "report.pdf") > 0 ? 0 : 3;
        } catch (const std::exception &e) {
            std::ofstream log(
                irforge::filesystemPath(option("--error-log", "irforge-gui-error.txt").toStdString()));
            log << e.what();
            return 2;
        }
    try {
        irforge::validatePipeName(pipe);
    } catch (...) {
        return 2;
    }
    irforge::MainWindow window(pipe);
    if (args.contains("--dark-theme"))
        for (auto *box : window.findChildren<QCheckBox *>())
            if (box->text() == "Dark theme")
                box->setChecked(true);
    window.show();
    QElapsedTimer elapsed;
    elapsed.start();
    auto screenshot = option("--screenshot", "");
    auto page = option("--page", "");
    if (!page.isEmpty())
        window.selectPage(page);
    auto incident = option("--open-incident", "");
    if (!incident.isEmpty())
        window.openIncident(incident.toStdString());
    if (!screenshot.isEmpty()) {
        auto *timer = new QTimer(&window);
        timer->setInterval(100);
        int *attempts = new int(0);
        QObject::connect(
            timer, &QTimer::timeout, &window,
            [&app, &window, timer, attempts, screenshot, &elapsed, option, incident] {
                bool ready =
                    incident.isEmpty() ? window.loaded() : window.property("incident_ready").toBool();
                auto expected = option("--expect-path", "");
                if (app.arguments().contains("--expect-request-failure"))
                    ready = window.property("request_failed").toBool();
                if (!expected.isEmpty())
                    ready = ready &&
                            window.visibleRows().dump().find(expected.toStdString()) != std::string::npos;
                if (ready) {
                    auto *target = QApplication::activeModalWidget();
                    bool ok = (target ? target->grab() : window.grab()).save(screenshot);
                    auto measure = option("--measurement", "");
                    if (!measure.isEmpty())
                        irforge::writeDocument(irforge::filesystemPath(measure.toStdString()),
                                               {{"schema_version", 1},
                                                {"elapsed_ms", elapsed.elapsed()},
                                                {"visible_rows", window.visibleRows().size()},
                                                {"expected_path", expected.toStdString()},
                                                {"measured_at", irforge::formatUtc(irforge::utcNow())},
                                                {"mode", "actual Qt display over authenticated local IPC"}});
                    timer->stop();
                    delete attempts;
                    app.exit(ok ? 0 : 3);
                } else if (++*attempts >= 300) {
                    timer->stop();
                    delete attempts;
                    app.exit(4);
                }
            });
        timer->start();
    }
    return app.exec();
}
