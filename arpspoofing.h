#ifndef ARPSPOOFING_H
#define ARPSPOOFING_H

#define HAVE_REMOTE

#include <QObject>
#include <QThread>
#include <stdio.h>
#include "include/pcap.h"
#include <conio.h>
#include "include/packet32.h"
#include <ntddndis.h>
#include "include/remote-ext.h"


//字节对齐必须是1
#pragma pack(1)
struct ethernet_head
{
    unsigned char dest_mac[6];   //目标主机MAC地址
    unsigned char source_mac[6]; //源端MAC地址
    unsigned short eh_type;      //以太网类型
};
struct arp_head
{
    unsigned short hardware_type; //硬件类型：以太网接口类型为1
    unsigned short protocol_type; //协议类型：IP协议类型为0X0800
    unsigned char add_len;        //硬件地址长度：MAC地址长度为6B
    unsigned char pro_len;        //协议地址长度：IP地址长度为4B
    unsigned short option;        //操作：ARP请求为1，ARP应答为2
    unsigned char sour_addr[6];   //源MAC地址：发送方的MAC地址
    unsigned long sour_ip;        //源IP地址：发送方的IP地址
    unsigned char dest_addr[6];   //目的MAC地址：ARP请求中该字段没有意义；ARP响应中为接收方的MAC地址
    unsigned long dest_ip;        //目的IP地址：ARP请求中为请求解析的IP地址；ARP响应中为接收方的IP地址
    unsigned char padding[18];
};
struct arp_packet //最终arp包结构
{
    ethernet_head eth; //以太网头部
    arp_head arp;      //arp数据包头部
};
#pragma pack()


class ARPSpoofing : public QThread
{
    Q_OBJECT
private:
    unsigned char *GetSelfMac(char *pDevName);
    unsigned char *BuildArpPacket(unsigned char *source_mac,unsigned long srcIP, unsigned long destIP);
    void init();
    void run();
    void sendSpoofingPackage();
    QString used_network_card;
    unsigned char *mac_addr;
    pcap_if_t *d;
    pcap_t *adhandle;
    QString target;
    QString gatewayIP;
public:
    void setParameter(QString,QString,QString,unsigned long,unsigned long);

    unsigned long ip;              //IP地址
    unsigned long netmask;         //子网掩码

};

#endif // ARPSPOOFING_H
