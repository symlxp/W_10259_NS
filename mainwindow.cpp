#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "selectnetworkcard.h"
#include "universaltools.h"
#include <QMessageBox>
#include <QDebug>
#include <QString>
#include "getdatapackage.h"
#include <QSql>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QDebug>
#include <QMessageBox>
#include <QDateTime>
#include <QString>
#include <QByteArray>
#include "parsedatapackage.h"

#define ARPS

int table_col_index = 0;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QVector<QMap<QString,QString>> z = getNetworkCardList();

    SelectNetworkCard *select_network_card_window = new SelectNetworkCard(this,z);
    select_network_card_window->exec();
    used_network_card = select_network_card_window->user_select;

    for (QMap<QString,QString> i : z){
        if(i["name"]==select_network_card_window->user_select){

            ip = i["address_int"].toULong();
            netmask = i["netmask_int"].toULong();
            break;

        }
    }

    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);

    connect(ui->tableWidget,&QTableWidget::clicked,this,&MainWindow::updatePackageWindow);

    ui->tableWidget->verticalHeader()->setVisible(false); //隐藏行表头
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);

    ui->tableWidget->setRowCount(0);
    ui->tableWidget->setColumnCount(8);

    QStringList table_header;
    table_header.push_back("序号");
    table_header.push_back("时间");
    table_header.push_back("源IP");
    table_header.push_back("目的IP");
    table_header.push_back("源MAC");
    table_header.push_back("目的MAC");
    table_header.push_back("数据包类型");
    table_header.push_back("数据包长度");
    ui->tableWidget->setHorizontalHeaderLabels(table_header);

//    db_path = localTime + ".db";

    connect(ui->start,&QPushButton::clicked,this,&MainWindow::startX);
    connect(ui->stop,&QPushButton::clicked,this,&MainWindow::stopX);

//    db = QSqlDatabase::addDatabase("QSQLITE");
//    db.setDatabaseName(db_path);
//    if (!db.open()) {
//        qDebug() << "DataBase open failed!";
//    }


}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::getPackage(PackageBrief x){
    ui->tableWidget->setRowCount(table_col_index+1);

    ui->tableWidget->setItem(table_col_index,0,new QTableWidgetItem(tr("%1").arg(x.package_id)));
    ui->tableWidget->setItem(table_col_index,1,new QTableWidgetItem(x.get_time));
    ui->tableWidget->setItem(table_col_index,2,new QTableWidgetItem(x.source_ip));
    ui->tableWidget->setItem(table_col_index,3,new QTableWidgetItem(x.target_ip));
    ui->tableWidget->setItem(table_col_index,4,new QTableWidgetItem(x.source_mac));
    ui->tableWidget->setItem(table_col_index,5,new QTableWidgetItem(x.target_mac));
    ui->tableWidget->setItem(table_col_index,6,new QTableWidgetItem(x.package_type));
    ui->tableWidget->setItem(table_col_index,7,new QTableWidgetItem(tr("%1").arg(x.total_length)));

    table_col_index++;
}


void MainWindow::updatePackageWindow(){

    if(x==NULL){
        return;
    }

   int cur_row = ui->tableWidget->currentRow();

    QSqlQuery sql_query;
    sql_query.prepare(tr("select * from packages where id = %1;").arg(cur_row+1));
    qDebug()<<"exec SQL:"<<tr("select * from packages where id = %1;").arg(cur_row+1);
    sql_query.exec();

//    u_char * data_raw;
    QByteArray data;
    while(sql_query.next()){
        data = sql_query.value(2).toByteArray();
    }

    const u_char *data_raw = (unsigned char*)data.data();

    ui->textBrowser_2->clear();

    if(ui->tableWidget->item(cur_row,6)->text()=="ARP"){
        ui->textBrowser_2->setText(parseARPPackage(data_raw));
//        break;
    }
        if(ui->tableWidget->item(cur_row,6)->text()=="TCP"){
        ui->textBrowser_2->setText(parseTCPPackage(data_raw));
//        break;
    }
        if(ui->tableWidget->item(cur_row,6)->text()=="UDP"){
        ui->textBrowser_2->setText(parseUDPPackage(data_raw));
//        break;
    }

        if(ui->tableWidget->item(cur_row,6)->text()=="ICMP"){
        ui->textBrowser_2->setText(parseICMPPackage(data_raw));
//        break;
    }


        QString data_hex = data.toHex();
        QString data_hex_formate;
        for (int i=1;i<data_hex.length();i++){
            data_hex_formate += data_hex[i];
            if(i%2==0&&i%16!=0){
                data_hex_formate+=" ";
            }
            if(i%16==0&&i){
                data_hex_formate += "\n";
            }
        }
        ui->textBrowser->setText(data_hex_formate);

}

void MainWindow::stopX(){

    if(x!=NULL){
        x->exit();
        x->terminate();
        x->packet_number = 1;
        x = NULL;
    }
#ifdef ARPS
    if(y!=NULL){
        y->exit();
        y->terminate();
        y = NULL;
    }
#endif
    ui->tableWidget->clearContents();
    ui->tableWidget->setRowCount(0);
    ui->textBrowser->clear();
    ui->textBrowser_2->clear();

    table_col_index = 0;

}

void MainWindow::startX(){

    if(x!=NULL){
        x->exit();
    }

#ifdef ARPS

    if(y!=NULL){
        y->exit();
    }

    y = new ARPSpoofing();
    y->netmask = netmask;
    y->ip = ip;
    y->setParameter(ui->lineEdit_3->text(),ui->lineEdit_2->text(),used_network_card,ip,netmask);
    y->start();
#endif

    x = new GetDataPackage();
    x->setParameter(ui->lineEdit->text());
    x->start();
    connect(this,SIGNAL(sendStartMSG(QString,QString)),x,SLOT(satrtGetDataPackage(QString,QString)));
    connect(x,SIGNAL(getDataPackage(PackageBrief)),this,SLOT(getPackage(PackageBrief)));
    qDebug()<<"1";

    qDebug()<<"2";

    QDateTime local(QDateTime::currentDateTime());
    QString localTime = local.toString("yyyy-MM-dd-hh-mm-ss");
    emit sendStartMSG(localTime+".db",used_network_card);

}


