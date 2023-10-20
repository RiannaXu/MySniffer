#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "mypcap.h"
#include "getAdapters.h"
#include "snifferthread.h"

#include <QMainWindow>
#include <QHostInfo>
#include <QStandardItemModel>
#include <QMessageBox>


using namespace std;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    SnifferThread *catchPacketThread = nullptr;

private slots:
    void trigerMenu(QAction*);
    void on_startButton_clicked(bool checked);
    void on_tableView_doubleClicked(const QModelIndex &index);
//    void append_text(int index, QStringList data, uint packet_len, const u_char *packet_data);
    void append_table(int index, QStringList data);
    void showTree(QStringList data);
    void showBinary(packetData data);
    void saveData(int index, QStringList data, uint packet_len, const u_char *packet_data);
    void on_countButton_clicked();

private:
    vector<NetworkAdapter> adapters;
    QVector<QStringList> packetVector;
    QVector<packetData> packetRaw;

    Ui::MainWindow *ui;
    QStandardItemModel *tableData;
    QStandardItemModel *treeData;

    void initComoBox();
    void initTable();
    void initTree();
    void initFilter();
    void messageBoxHelp();
    void messageBoxMore();
};
#endif // MAINWINDOW_H
