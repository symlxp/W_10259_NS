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
};

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
