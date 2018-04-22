#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "selectnetworkcard.h"
#include "universaltools.h"
#include <QMessageBox>
#include <QDebug>

#include "getdatapackage.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    SelectNetworkCard *select_network_card_window = new SelectNetworkCard(this,getNetworkCardList());
    select_network_card_window->exec();
    used_network_card = select_network_card_window->user_select;


//    Worker * worker

    GetDataPackage *x = new GetDataPackage();

    x->start();

    connect(this,SIGNAL(sendStartMSG(QString,QString)),x,SLOT(satrtGetDataPackage(QString,QString)));
    connect(x,SIGNAL(getDataPackage(PackageBrief)),this,SLOT(getPackage(PackageBrief)));

    emit sendStartMSG(tr("x.db"),used_network_card);

    connect(ui->pushButton,&QPushButton::clicked,this,&MainWindow::xx);



}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::getPackage(PackageBrief x){
    qDebug()<<"---"<<x.source_ip;
}


void MainWindow::xx(){

    emit sendStartMSG(tr("x.db"),used_network_card);


}
