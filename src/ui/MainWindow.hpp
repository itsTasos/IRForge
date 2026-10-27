#pragma once
#include "irforge/core/Event.hpp"
#include <QFutureWatcher>
#include <QMainWindow>
#include <functional>
class QListWidget;
class QTableWidget;
class QLabel;
class QLineEdit;
class QComboBox;
class QPushButton;
class QDialog;
namespace irforge {
class MainWindow final : public QMainWindow {
    std::string pipe_;
    QListWidget *navigation_;
    QTableWidget *table_;
    QLabel *summary_;
    QLineEdit *search_, *host_, *pid_;
    QComboBox *severity_, *state_, *type_, *source_;
    bool localTime_ = false;
    QPushButton *previous_, *next_;
    Json rows_ = Json::array();
    int offset_ = 0, generation_ = 0;
    bool refreshInFlight_ = false, refreshPending_ = false;
    bool administrator_ = false;
    QDialog *controlPanel_ = nullptr;
    void refresh();
    void detail(int row);
    void showIncident(const Json &);
    void async(const std::function<Json()> &, const std::function<void(const Json &)> &, int generation = -1);
    void mutate(const Json &, const std::function<void(const Json &)> &);
    void closeEvent(QCloseEvent *event) override;

  public:
    explicit MainWindow(std::string pipe);
    void openControlPanel();
    void selectPage(const QString &);
    void openIncident(const std::string &id);
    bool loaded() const;
    Json visibleRows() const { return rows_; }
};
} // namespace irforge
