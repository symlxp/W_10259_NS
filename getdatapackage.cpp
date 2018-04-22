#include "getdatapackage.h"
#include <QByteArray>
#include <QSqlQuery>

#define DSQL qDebug()<<"exec SQL->"<<

GetDataPackage * super_this;
QSqlDatabase db;

void GetDataPackage::run(){

//    moveToThread(this);

    super_this = this;

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

    db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(db_path);
    if(!db.open()){
        qDebug()<<"DataBase open failed!";
    }

    QSqlQuery sql_query;

    sql_query.prepare("create table packages(id int  primary key, time text,data blob);");
    DSQL"create table packages(id int  primary key, time text,data blob);";
    sql_query.exec();

    pcap_loop(adhandle, 0, packetHandler, NULL);

//    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){

////        QMessageBox::information(NULL,"x","y");


//        if(res == 0)
//            /* 超时时间到 */
//            continue;

//        /* 将时间戳转换成可识别的格式 */
//        local_tv_sec = header->ts.tv_sec;
//        ltime=localtime(&local_tv_sec);
//        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

//        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
//        qDebug()<<timestr<<header->ts.tv_usec<<header->len;
//        PackageBrief x;
//        x.source_ip = tr("%1%2%3").arg(timestr).arg(header->ts.tv_usec).arg(header->len);
//        emit getDataPackage(x);
//    }


}



void GetDataPackage::satrtGetDataPackage(QString db_path,QString dev_name){

    this->db_path = db_path;
    this->dev_name = dev_name;
    used_network_card = dev_name;

}

long long package_id = 0;

void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
//    header->

    /* 打印数据包的时间戳和长度 */
    printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

    /* 获得IP数据包头部的位置 */
    ih = (ip_header *) (pkt_data +
        14); //以太网头部长度

    /* 获得UDP首部的位置 */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    /* 将网络字节序列转换成主机字节序列 */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

    PackageBrief x;
    x.package_id = package_id;
    x.type_of_service = ih->tos;
    x.total_length = ih->tlen;
    x.time_to_live = ih->ttl;
    x.protocol = ih->proto;
    x.header_checksum = ih->crc;
    x.udp_dport = dport;
    x.udp_sport = sport;
    x.udp_len = uh->len;
    x.get_time = timestr;
    x.source_ip = QObject::tr("%1.%2.%3.%4").arg(ih->saddr.byte1).arg(ih->saddr.byte2).arg(ih->saddr.byte3).arg(ih->saddr.byte4);
    x.target_ip = QObject::tr("%1.%2.%3.%4").arg(ih->daddr.byte1).arg(ih->daddr.byte2).arg(ih->daddr.byte3).arg(ih->daddr.byte4);
    emit super_this->getDataPackage(x);

    QSqlQuery sql_query;

    sql_query.prepare("insert into packages values (?, ?, ?)");
    sql_query.addBindValue(package_id++);
    sql_query.addBindValue(timestr);
    QByteArray databuf;
    databuf = QByteArray::fromRawData((char*)pkt_data,-1);
    sql_query.addBindValue(databuf);
    sql_query.exec();
}












































