#ifndef GETDATAPACKAGE_H
#define GETDATAPACKAGE_H


#define HAVE_REMOTE

#include <QObject>
#include <QThread>
#include <stdio.h>
#include "include/pcap.h"
#include <conio.h>
#include "include/packet32.h"
#include <ntddndis.h>
#include "include/remote-ext.h"
#include <cstring>
#include <QSql>
#include <QSqlDatabase>
#include <QDebug>
#include <QMessageBox>
#include <QDateTime>
#include <QString>


struct PackageBrief
{
    long long package_id;

    QString source_ip;
    QString source_mac;
    QString target_ip;
    QString target_mac;
    int total_length;
    int type_of_service;
    int time_to_live;
    int protocol;
    int header_checksum;
    int udp_sport;
    int udp_dport;
    int udp_len;
    QString get_time;
    QString package_type;
};

/* 4字节的IP地址 */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;


struct ArpHeader
{
    unsigned short hdtyp;   //硬件类型
    unsigned short protyp;   //协议类型
    unsigned char hdsize;   //硬件地址长度
    unsigned char prosize;   //协议地址长度
    unsigned short op;   //操作类型，ARP请求（1），ARP应答（2），RARP请求（3），RARP应答（4）。
    u_char smac[6];   //源MAC地址
    u_char sip[4];   //源IP地址
    u_char dmac[6];   //目的MAC地址
    u_char dip[4];   //目的IP地址
};

/* UDP 首部*/
typedef struct udp_header{
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_short len;            // UDP数据包长度(Datagram length)
    u_short crc;            // 校验和(Checksum)
}udp_header;

/*以太网协议头*/
struct ether_header
{
    u_int8_t ether_dhost[6]; //目的Mac地址
    u_int8_t ether_shost[6]; //源Mac地址
    u_int16_t ether_type;    //协议类型
};
/*IPv4协议头*/
struct ip_header
{
#if defined(WORDS_BIENDIAN)
    u_int8_t    ip_version : 4, ip_header_length : 4;
#else
    u_int8_t    ip_header_length : 4, ip_version : 4;
#endif
    u_int8_t    ip_tos;
    u_int16_t   ip_length;
    u_int16_t   ip_id;
    u_int16_t   ip_off;
    u_int8_t    ip_ttl;
    u_int8_t    ip_protocol;
    u_int16_t   ip_checksum;
    ip_address  saddr;          /*源地址(Source address)*/
    ip_address  daddr;          /*目的地址(Destination address)*/
};
/*UDP协议头*/
struct udphdr
{
    u_int16_t source_port; /*源地址端口*/
    u_int16_t dest_port;    /*目的地址端口*/
    u_int16_t len;     /*UDP长度*/
    u_int16_t check;   /*UDP校验和*/
};
//TCP协议头
#define __LITTLE_ENDIAN_BITFIELD
struct tcphdr
{
    u_int16_t   source_port;         /*源地址端口*/
    u_int16_t   dest_port;           /*目的地址端口*/
    u_int32_t   seq;            /*序列号*/
    u_int32_t   ack_seq;        /*确认序列号*/
    u_int8_t    tcp_header_length : 4;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    u_int16_t res1 : 4,   /*保留*/
        doff : 4,             /*偏移*/
        fin : 1,              /*关闭连接标志*/
        syn : 1,              /*请求连接标志*/
        rst : 1,              /*重置连接标志*/
        psh : 1,              /*接收方尽快将数据放到应用层标志*/
        ack : 1,              /*确认序号标志*/
        urg : 1,              /*紧急指针标志*/
        ece : 1,              /*拥塞标志位*/
        cwr : 1;              /*拥塞标志位*/
#elif defined(__BIG_ENDIAN_BITFIELD)
    u_int16_t doff : 4,   /*偏移*/
        res1 : 4,             /*保留*/
        cwr : 1,              /*拥塞标志位*/
        ece : 1,              /*拥塞标志位*/
        urg : 1,              /*紧急指针标志*/
        ack : 1,              /*确认序号标志*/
        psh : 1,              /*接收方尽快将数据放到应用层标志*/
        rst : 1,              /*重置连接标志*/
        syn : 1,              /*请求连接标志*/
        fin : 1;              /*关闭连接标志*/
#else
    u_int16_t   flag;
#endif
    u_int16_t   window;         /*滑动窗口大小*/
    u_int16_t   check;          /*校验和*/
    u_int16_t   urg_ptr;        /*紧急字段指针*/
};

//void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
QString ip_protool_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
void tcp_protool_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
void udp_protool_packet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);

class GetDataPackage : public QThread
{
    Q_OBJECT

public:
    void run();
    void init();
    void exit();
    int packet_number = 1;

private:

    QString used_network_card;
    pcap_if_t *d;
    pcap_t *adhandle;
    QString db_path;
    QString dev_name;
    QString filter_rule;
public:
    void setParameter(QString);

public slots:
    void satrtGetDataPackage(QString,QString);

signals:
    void getDataPackage(PackageBrief);

};

#endif // GETDATAPACKAGE_H
