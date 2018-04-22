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
    QString target_ip;
    int total_length;
    int type_of_service;
    int time_to_live;
    int protocol;
    int header_checksum;
    int udp_sport;
    int udp_dport;
    int udp_len;
    QString get_time;
};

/* 4字节的IP地址 */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header{
    u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  tos;            // 服务类型(Type of service)
    u_short tlen;           // 总长(Total length)
    u_short identification; // 标识(Identification)
    u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char  ttl;            // 存活时间(Time to live)
    u_char  proto;          // 协议(Protocol)
    u_short crc;            // 首部校验和(Header checksum)
    ip_address  saddr;      // 源地址(Source address)
    ip_address  daddr;      // 目的地址(Destination address)
    u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

/* UDP 首部*/
typedef struct udp_header{
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_short len;            // UDP数据包长度(Datagram length)
    u_short crc;            // 校验和(Checksum)
}udp_header;

void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

class GetDataPackage : public QThread
{
    Q_OBJECT

public:
    void run();
    void init();

private:

    QString used_network_card;
    pcap_if_t *d;
    pcap_t *adhandle;
    QString db_path;
    QString dev_name;

public slots:
    void satrtGetDataPackage(QString,QString);

signals:
    void getDataPackage(PackageBrief);

};

#endif // GETDATAPACKAGE_H
