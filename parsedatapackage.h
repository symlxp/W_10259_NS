#ifndef PARSEDATAPACKAGE_H
#define PARSEDATAPACKAGE_H

#include <QString>
#include <QDebug>

typedef unsigned char u_char;

//ICMP基本头部
struct ICMP
{
    unsigned char Type;//8位类型
    unsigned char  Code;//8位代码
    unsigned short  Checksum;//16位校验和
};

QString parseARPPackage(const u_char* data);
//QString parseHTTPPackage(const u_char* data);
QString parseTCPPackage(const u_char* data);
QString parseUDPPackage(const u_char* data);
QString parseICMPPackage(const u_char* data);

#endif // PARSEDATAPACKAGE_H
