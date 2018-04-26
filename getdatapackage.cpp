#include "getdatapackage.h"
#include <QByteArray>
#include <QSqlQuery>

#define DSQL qDebug()<<"exec SQL->"<<

GetDataPackage * super_this;
QSqlDatabase db;

void GetDataPackage::run() {

//    moveToThread(this);

    super_this = this;

    while (dev_name == "") {
        ;
    }

    qDebug()<<"3";

    init();

    qDebug()<<"4";

}


void GetDataPackage::init() {

    pcap_if_t *alldevs;            //全部网卡列表
    int i = 0;                     //循环变量
    char errbuf[PCAP_ERRBUF_SIZE]; //错误缓冲区

    /* 获得本机网卡列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s/n", errbuf);
        exit();
    }

    /* 移动指针到用户选择的网卡 */
    for (d = alldevs, i = 0; strcmp(d->name + 8, used_network_card.toStdString().c_str()); d = d->next, i++)
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

    u_int netmask;

    struct bpf_program fcode;

    if(d->addresses != NULL)
            /* 获得接口第一个地址的掩码 */
            netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
        else
            /* 如果接口没有地址，那么我们假设一个C类的掩码 */
            netmask=0xffffff;


        //编译过滤器
        if (pcap_compile(adhandle, &fcode, filter_rule.toStdString().c_str(), 1, netmask) <0 )
        {
            fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
            /* 释放设备列表 */
            pcap_freealldevs(alldevs);
            this->terminate();
            return;
        }

        //设置过滤器
        if (pcap_setfilter(adhandle, &fcode)<0)
        {
            fprintf(stderr,"\nError setting the filter.\n");
            /* 释放设备列表 */
            pcap_freealldevs(alldevs);
            this->terminate();
            return;
        }

    pcap_freealldevs(alldevs);

    qDebug() << "get db path:" << db_path;

    used_network_card = dev_name;

    db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(db_path);
    if (!db.open()) {
        qDebug() << "DataBase open failed!";
    }

    QSqlQuery sql_query;

    sql_query.prepare("create table packages(id int  primary key, time text,data blob);");
    DSQL"create table packages(id int  primary key, time text,data blob);";
    sql_query.exec();

    pcap_loop(adhandle, 0, ethernet_protocol_packet_callback, NULL);

//    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){

////        QMessageBox::information(NULL,"x","y");


//        if(res == 0)
//            /* 超时时间到 */
//            continue;

//        /* 将时间戳转换成可识别的格式 */
//        local_tv_sec = header->ts.tv_sec;
//        ltime=localtime(&local_tv_sec);
//        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

//        //printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
//        qDebug()<<timestr<<header->ts.tv_usec<<header->len;
//        PackageBrief x;
//        x.source_ip = tr("%1%2%3").arg(timestr).arg(header->ts.tv_usec).arg(header->len);
//        emit getDataPackage(x);
//    }


}



void GetDataPackage::satrtGetDataPackage(QString db_path, QString dev_name) {

    this->db_path = db_path;
    this->dev_name = dev_name;
    used_network_card = dev_name;

}

long long package_id = 0;

//void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
//{
//    struct tm *ltime;
//    char timestr[16];
//    ip_header *ih;
//    udp_header *uh;
//    u_int ip_len;
//    u_short sport,dport;
//    time_t local_tv_sec;

//    /* 将时间戳转换成可识别的格式 */
//    local_tv_sec = header->ts.tv_sec;
//    ltime=localtime(&local_tv_sec);
//    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
////    header->

//    /* 打印数据包的时间戳和长度 */
////    //printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

//    /* 获得IP数据包头部的位置 */
//    ih = (ip_header *) (pkt_data +
//        14); //以太网头部长度



//    /* 获得UDP首部的位置 */
//    ip_len = (ih->ver_ihl & 0xf) * 4;

//    uh = (udp_header *) ((u_char*)ih + ip_len);

//    /* 将网络字节序列转换成主机字节序列 */
//    sport = ntohs( uh->sport );
//    dport = ntohs( uh->dport );

//    PackageBrief x;
//    x.package_id = package_id;
//    x.type_of_service = ih->tos;
//    x.total_length = ih->tlen;
//    x.time_to_live = ih->ttl;
//    x.protocol = ih->proto;
//    x.header_checksum = ih->crc;
//    x.udp_dport = dport;
//    x.udp_sport = sport;
//    x.udp_len = uh->len;
//    x.get_time = timestr;
//    x.source_ip = QObject::tr("%1.%2.%3.%4").arg(ih->saddr.byte1).arg(ih->saddr.byte2).arg(ih->saddr.byte3).arg(ih->saddr.byte4);
//    x.target_ip = QObject::tr("%1.%2.%3.%4").arg(ih->daddr.byte1).arg(ih->daddr.byte2).arg(ih->daddr.byte3).arg(ih->daddr.byte4);
//    emit super_this->getDataPackage(x);

//    QSqlQuery sql_query;

//    sql_query.prepare("insert into packages values (?, ?, ?)");
//    sql_query.addBindValue(package_id++);
//    sql_query.addBindValue(timestr);
//    QByteArray databuf;
//    databuf = QByteArray::fromRawData((char*)pkt_data,-1);
//    sql_query.addBindValue(databuf);
//    sql_query.exec();
//}

//void udp_protool_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
//{
//    struct udphdr *udp_protocol;
//    u_int header_length = 0;
//    u_int16_t checksum;
//    udp_protocol = (struct udphdr *) packet_content;
//    checksum = ntohs(udp_protocol->check);
//    u_int16_t source_port; /*源地址端口*/
//    u_int16_t dest_port;    /*目的地址端口*/
//    u_int16_t len;     /*UDP长度*/
//    u_int16_t check;   /*UDP校验和*/
//    //printf("---------UDP协议---------\n");
//    //printf("源端口:%d\n", ntohs(udp_protocol->source_port));
//    //printf("目的端口:%d\n", ntohs(udp_protocol->dest_port));
//    //printf("UDP数据包长度:%d\n", ntohs(udp_protocol->len));
//    //printf("UDP校验和:%d\n", checksum);
//}
////TCP协议分析
//void tcp_protool_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
//{
//    struct tcphdr *tcp_protocol;
//    u_int header_length = 0;
//    u_int offset;
//    u_char tos;
//    u_int16_t checksum;
//    tcp_protocol = (struct tcphdr *) packet_content;
//    checksum = ntohs(tcp_protocol->check);
//    //printf("---------TCP协议---------\n");
//    //printf("源端口:%d\n", ntohs(tcp_protocol->source_port));
//    //printf("目的端口:%d\n", ntohs(tcp_protocol->dest_port));
//    //printf("SEQ:%d\n", ntohl(tcp_protocol->seq));
//    //printf("ACK SEQ:%d\n", ntohl(tcp_protocol->ack_seq));
//    //printf("TCP校验和:%d\n", checksum);
//    if (ntohs(tcp_protocol->source_port) == 80 || ntohs(tcp_protocol->dest_port) == 80)//http协议
//        //printf("http data:\n%s\n", packet_content + sizeof(tcphdr));
//}
//IP协议分析
//QString ip_protool_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
//{
//    struct ip_header *ip_protocol;
//    u_int offset;
//    u_char tos;
//    u_int16_t checksum;
//    ip_protocol = (struct ip_header *)packet_content;
//    checksum = ntohs(ip_protocol->ip_checksum);
//    tos = ip_protocol->ip_tos;
//    offset = ntohs(ip_protocol->ip_off);
//    //printf("---------IP协议---------\n");
//    //printf("版本号:%d\n", ip_protocol->ip_version);
//    //printf("首部长度:%d\n", ip_protocol->ip_header_length);
//    //printf("服务质量:%d\n", tos);
//    //printf("总长度:%d\n", ntohs(ip_protocol->ip_length));
//    //printf("标识:%d\n", ntohs(ip_protocol->ip_id));
//    //printf("偏移:%d\n", (offset & 0x1fff) * 8);
//    //printf("生存时间:%d\n", ip_protocol->ip_ttl);
//    //printf("协议类型:%d\n", ip_protocol->ip_protocol);
//    //printf("检验和:%d\n", checksum);
//    //printf("源IP地址:%d.%d.%d.%d\n", ip_protocol->saddr.byte1, ip_protocol->saddr.byte2, ip_protocol->saddr.byte3, ip_protocol->saddr.byte4);
//    //printf("目的地址:%d.%d.%d.%d\n", ip_protocol->daddr.byte1, ip_protocol->daddr.byte2, ip_protocol->daddr.byte3, ip_protocol->daddr.byte4);
//    switch (ip_protocol->ip_protocol)
//    {
//    case 1: //printf("上层协议是ICMP协议\n"); return "ICMP";break;
//    case 2: //printf("上层协议是IGMP协议\n"); return "IGMP";break;
//    case 6:
//    {
//        //printf("上层协议是TCP协议\n");
//        tcp_protool_packet_callback(argument, packet_header, packet_content + sizeof(ip_header));
//        return "TCP";
//    }
//    break;
//    case 17:
//    {
//        //printf("上层协议是UDP协议\n");
//        udp_protool_packet_callback(argument, packet_header, packet_content + sizeof(ip_header));
//        return "UDP";
//    }
//    break;
//    default:break;
//    }
//}


void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
    u_short ethernet_type;
    struct ether_header *ethernet_protocol;
    u_char mac_string[6];
    //printf("----------------------------------------------\n");
    //printf("捕获第%d个网络数据包\n", packet_number);
    //printf("该数据包的具体内容：\n");
//    for (int i = 1; i <= packet_header->len; i++)
//    {
//        //printf("%02x ", packet_content[i - 1]);
//        if (i % 8 == 0)
//            //printf(" ");
//        if (i % 16 == 0)
//            //printf("\n");
//    }
    //printf("\n");
    PackageBrief ret;

    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = packet_header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    ret.get_time = timestr;

    //printf("数据包长度:%d\n", packet_header->len);
    ret.total_length = packet_header->len;
    //printf("---------以太网协议---------\n");
    ethernet_protocol = (struct ether_header*)packet_content;//获得数据包内容
    ethernet_type = ntohs(ethernet_protocol->ether_type);//获得以太网类型
    //printf("以太网类型:%04x\n", ethernet_type);
    ret.protocol = ethernet_type;
    memcpy(mac_string, ethernet_protocol->ether_shost, sizeof(mac_string));
    //printf("MAC帧源地址:%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
    char s_mac[28];
    sprintf(s_mac, "%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
    memcpy(mac_string, ethernet_protocol->ether_dhost, sizeof(mac_string));
    //printf("MAC帧目的地址:%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
    char d_mac[28];
    sprintf(d_mac, "%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
    ret.source_mac = s_mac;
    ret.target_mac = d_mac;
    switch (ethernet_type)
    {
    case 0x0800:
    {
        switch (((struct ip_header *)(packet_content + sizeof(ether_header)))->ip_protocol) {
        case 1: {
            ret.package_type = "ICMP";

            break;
        }
        case 2: {
            ret.package_type = "IGMP";
            break;
        }
        case 6: {
            ret.package_type = "TCP";
            break;
        }
        case 17: {
            ret.package_type = "UDP";
            break;
        }
        default:
            break;
        }

        struct ip_header *ip_protocol;
        ip_protocol = (struct ip_header *)(packet_content + sizeof(ether_header));
        ip_address s_ip_addr = ip_protocol->saddr;
        ip_address d_ip_addr = ip_protocol->daddr;
        ret.source_ip = QObject::tr("%1.%2.%3.%4").arg(s_ip_addr.byte1).arg(s_ip_addr.byte2).arg(s_ip_addr.byte3).arg(s_ip_addr.byte4);
        ret.target_ip = QObject::tr("%1.%2.%3.%4").arg(d_ip_addr.byte1).arg(d_ip_addr.byte2).arg(d_ip_addr.byte3).arg(d_ip_addr.byte4);

        //printf("上层协议是IPv4协议\n");
        break;
    }
    case 0x0806: {
        //printf("上层协议是ARP协议\n");
        ret.package_type = "ARP";
        ArpHeader* arph = (ArpHeader *)(packet_content + 14);
        ip_address s_ip_addr;
        memcpy(&s_ip_addr, arph->sip, sizeof(s_ip_addr));
        ip_address d_ip_addr;
        memcpy(&d_ip_addr, arph->dip, sizeof(d_ip_addr));
        ret.source_ip = QObject::tr("%1.%2.%3.%4").arg(s_ip_addr.byte1).arg(s_ip_addr.byte2).arg(s_ip_addr.byte3).arg(s_ip_addr.byte4);
        ret.target_ip = QObject::tr("%1.%2.%3.%4").arg(d_ip_addr.byte1).arg(d_ip_addr.byte2).arg(d_ip_addr.byte3).arg(d_ip_addr.byte4);
        break;
    }
    case 0x8035: {
        //printf("上层协议是RARP协议\n");
        ret.package_type = "RARP";
        break;
    }
    case 0x814C: {
        //printf("上层协议是简单网络管理协议SNMP\n");
        ret.package_type = "SNMP";
        break;
    }
    case 0x004f: {
        ret.package_type = "锐捷专有协议";
        break;
    }
    case 0x8137: {
        //printf("上层协议是因特网包交换（IPX：Internet Packet Exchange）\n");
        ret.package_type = "IPX";
        break;
    }
    case 0x86DD: {
        return;
        //printf("上层协议是IPv6协议\n");
        ret.package_type = "IPv6";
        break;
    }
    case 0x880B: {
        //printf("上层协议是点对点协议（PPP：Point-to-Point Protocol）\n");
        ret.package_type = "PPP";
        break;
    }
    default: break;
    }
    //printf("----------------------------------------------\n");

    QSqlQuery sql_query;

    sql_query.prepare("insert into packages values (?, ?, ?)");
    sql_query.addBindValue(super_this->packet_number);
    sql_query.addBindValue(timestr);
    QByteArray databuf;
    databuf = QByteArray::fromRawData((char*)packet_content, packet_header->len);
    sql_query.addBindValue(databuf);
    sql_query.exec();

    ret.package_id = super_this->packet_number;
    emit super_this->getDataPackage(ret);
    (super_this->packet_number)++;
}

void GetDataPackage::exit(){

    db.close();

}

void GetDataPackage::setParameter(QString fileter){

    filter_rule = fileter;

}





































