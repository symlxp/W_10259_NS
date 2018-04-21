#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "selectnetworkcard.h"
#include "universaltools.h"
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    SelectNetworkCard *select_network_card_window = new SelectNetworkCard(this,getNetworkCardList());
    select_network_card_window->exec();


}

MainWindow::~MainWindow()
{
    delete ui;
}
