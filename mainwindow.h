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
    void xx();

public:
    QString used_network_card;

public slots:
    void getPackage(PackageBrief);

signals:
    void sendStartMSG(QString,QString);

};

#endif // MAINWINDOW_H
