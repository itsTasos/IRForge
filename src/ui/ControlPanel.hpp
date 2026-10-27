#pragma once
#include <QDialog>
#include <string>

class QProcess;
class QLineEdit;
class QPlainTextEdit;
class QCheckBox;
class QSpinBox;
class QLabel;
class QPushButton;

namespace irforge {
class ControlPanel final : public QDialog {
    std::string pipe_;
    QProcess *process_;
    QLineEdit *configPath_, *rulesPath_, *outputPath_, *roots_;
    QPlainTextEdit *editor_, *log_;
    QCheckBox *processEvents_, *network_, *registry_, *file_, *inventory_, *eventLog_, *yara_, *commands_;
    QSpinBox *duration_;
    QLabel *status_;
    QPushButton *start_, *stop_, *openRecording_;
    void *stopEvent_ = nullptr;
    QString sessionPath_;
    void loadConfig();
    bool saveConfig();
    void populate();
    void applyFields();
    void startMonitor();
    void openRecording();
    void stopMonitor();
    void closeEvent(QCloseEvent *event) override;

  public:
    explicit ControlPanel(std::string pipe, QWidget *parent = nullptr);
    bool monitoring() const;
};
} // namespace irforge
