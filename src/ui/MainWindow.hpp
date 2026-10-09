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
    bool administrator_ = false;
    void refresh();
    void detail(int row);
    void showIncident(const Json &);
    void async(const std::function<Json()> &, const std::function<void(const Json &)> &);
    void mutate(const Json &, const std::function<void(const Json &)> &);

  public:
    explicit MainWindow(std::string pipe);
    void selectPage(const QString &);
    void openIncident(const std::string &id);
    bool loaded() const;
    Json visibleRows() const { return rows_; }
};
} // namespace irforge
