#ifndef UNIVERSALTOOLS_H
#define UNIVERSALTOOLS_H

#include <QMap>
#include <QVector>
#include <QString>
#include "include/pcap.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <conio.h>
#include <include/packet32.h>
#include <ntddndis.h>

QVector<QMap<QString, QString>> getNetworkCardList();
char *iptos(u_long);

#endif // UNIVERSALTOOLS_H
