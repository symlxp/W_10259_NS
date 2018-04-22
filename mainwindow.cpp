#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "selectnetworkcard.h"
#include "universaltools.h"
#include <QMessageBox>
#include <QDebug>
#include <QString>
#include "getdatapackage.h"

int table_col_index = 0;
QMap<int,QString> protocol_table;

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

    ui->tableWidget->verticalHeader()->setVisible(false); //隐藏行表头
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);

    ui->tableWidget->setRowCount(0);
    ui->tableWidget->setColumnCount(5);

    QStringList table_header;
    table_header.push_back("时间");
    table_header.push_back("源IP");
    table_header.push_back("目的IP");
    table_header.push_back("数据包类型");
    table_header.push_back("数据包长度");
    ui->tableWidget->setHorizontalHeaderLabels(table_header);

    protocol_table[1] = "ICMP";
    protocol_table[2] = "IGMP";
    protocol_table[6] = "TCP";
    protocol_table[17] = "UDP";
    protocol_table[88] = "IGRP";
    protocol_table[89] = "OSPF";

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::getPackage(PackageBrief x){
    ui->tableWidget->setRowCount(table_col_index+1);

    ui->tableWidget->setItem(table_col_index,0,new QTableWidgetItem(x.get_time));
    ui->tableWidget->setItem(table_col_index,1,new QTableWidgetItem(x.source_ip));
    ui->tableWidget->setItem(table_col_index,2,new QTableWidgetItem(x.target_ip));
    ui->tableWidget->setItem(table_col_index,3,new QTableWidgetItem(protocol_table[x.protocol]));
    ui->tableWidget->setItem(table_col_index,4,new QTableWidgetItem(tr("%1").arg(x.total_length)));

    table_col_index++;
}

