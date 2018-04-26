#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "arpspoofing.h"
#include "getdatapackage.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QString getRawData();
    QSqlDatabase db;
    QString db_path;
    void updatePackageWindow();
    void startX();
    void stopX();
    GetDataPackage *x = NULL;
    ARPSpoofing *y = NULL;
    unsigned long ip;              //IP地址
    unsigned long netmask;         //子网掩码

public:
    QString used_network_card;

public slots:
    void getPackage(PackageBrief);

signals:
    void sendStartMSG(QString,QString);

};

#endif // MAINWINDOW_H
