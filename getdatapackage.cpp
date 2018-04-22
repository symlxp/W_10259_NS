#include "getdatapackage.h"
#include <QSql>
#include <QSqlDatabase>
#include <QDebug>
#include <QMessageBox>
#include <QDateTime>

void GetDataPackage::run(){

//    moveToThread(this);

    while(dev_name==""){
        ;
    }

    init();

}


void GetDataPackage::init(){

    pcap_if_t *alldevs;            //全部网卡列表
        int i = 0;                     //循环变量
        char errbuf[PCAP_ERRBUF_SIZE]; //错误缓冲区

    /* 获得本机网卡列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s/n", errbuf);
        exit(1);
    }

    /* 移动指针到用户选择的网卡 */
    for (d = alldevs, i = 0; strcmp(d->name+8,used_network_card.toStdString().c_str()); d = d->next, i++)
        ;

    if ((adhandle = pcap_open(d->name, // name of the device
                              65536,   // portion of the packet to capture
                              0,       //open flag
                              1000,    // read timeout
                              NULL,    // authentication on the remote machine
                              errbuf   // error buffer
                              )) == NULL)
    {
        fprintf(stderr, "/nUnable to open the adapter. %s is not supported by WinPcap/n",
                d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return;
    }

    pcap_freealldevs(alldevs);

    qDebug()<<"get db path:"<<db_path;

    used_network_card = dev_name;

    int res;
    struct tm *ltime;
    char timestr[16];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t local_tv_sec;

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(db_path);
    if(!db.open()){
        qDebug()<<"DataBase open failed!";
    }


    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){

//        QMessageBox::information(NULL,"x","y");


        if(res == 0)
            /* 超时时间到 */
            continue;

        /* 将时间戳转换成可识别的格式 */
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
        qDebug()<<timestr<<header->ts.tv_usec<<header->len;
        PackageBrief x;
        x.source_ip = tr("%1%2%3").arg(timestr).arg(header->ts.tv_usec).arg(header->len);
        emit getDataPackage(x);
    }


}



void GetDataPackage::satrtGetDataPackage(QString db_path,QString dev_name){

    this->db_path = db_path;
    this->dev_name = dev_name;
    used_network_card = dev_name;

}















































