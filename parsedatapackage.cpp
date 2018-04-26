#include "parsedatapackage.h"
#include "getdatapackage.h"

QString parseIPPackage(const u_char* data) {

    QString ret;

    struct ip_header *ip_protocol;
    u_int offset;
    u_char tos;
    u_int16_t checksum;
    ip_protocol = (struct ip_header *)(data + sizeof(ether_header));
    checksum = ntohs(ip_protocol->ip_checksum);
    tos = ip_protocol->ip_tos;
    offset = ntohs(ip_protocol->ip_off);
    ret += QObject::tr("版本号:%1\n").arg(ip_protocol->ip_version);
    ret += QObject::tr("首部长度:%1\n").arg(ip_protocol->ip_header_length);
    ret += QObject::tr("服务质量:%1\n").arg(tos);
    ret += QObject::tr("总长度:%1\n").arg(ntohs(ip_protocol->ip_length));
    ret += QObject::tr("标识:%1\n").arg(ntohs(ip_protocol->ip_id));
    ret += QObject::tr("偏移:%1\n").arg((offset & 0x1fff) * 8);
    ret += QObject::tr("生存时间:%1\n").arg(ip_protocol->ip_ttl);
    ret += QObject::tr("协议类型:%1\n").arg(ip_protocol->ip_protocol);
    ret += QObject::tr("检验和:%1\n").arg(checksum);
//        ret += QObject::tr("源IP地址:%1.%2.%3.%4\n").arg(ip_protocol->saddr.byte1).arg(ip_protocol->saddr.byte2).arg(ip_protocol->saddr.byte3).arg(ip_protocol->saddr.byte4);
//        ret += QObject::tr("目的IP地址:%1.%2.%3.%4\n").arg(ip_protocol->daddr.byte1).arg(ip_protocol->daddr.byte2).arg(ip_protocol->daddr.byte3).arg(ip_protocol->daddr.byte4);

    return ret;

}
QString parseICMPPackage(const u_char* data) {

    QString ret;

//        struct ip_header * x = (data + sizeof(ether_header));


        struct ICMP* Icmp;
        Icmp = (struct ICMP *)( data+sizeof(ether_header)+sizeof(ip_header));
        ret+="ICMP类型:";
        switch (Icmp->Type)
        {
        case 0:
            ret+=("回显应答");
            break;
        case 8:
            ret+=("回显请求");
            break;
        case 13:
            ret+=("时间戳请求");
            break;
        case 14:
            ret+=("时间戳应答");
            break;
        case 17:
            ret+=("地址掩码请求");
            break;
        case 18:
            ret+=("地址掩码应答");
            break;
        default:
            ret+=("ICMP类型未知");
            break;
        }
        ret+=QObject::tr("\nICMP Code:%1\n").arg(Icmp->Code);
        ret+=QObject::tr("ICMP Checksum:%1\n").arg(ntohs(Icmp->Checksum));

    return ret;

}

QString parseARPPackage(const u_char* data) {

	QString ret;

	ArpHeader* arph = (ArpHeader *)(data + 14);
	ip_address s_ip_addr;
	memcpy(&s_ip_addr, arph->sip, sizeof(s_ip_addr));
	ip_address d_ip_addr;
	memcpy(&d_ip_addr, arph->dip, sizeof(d_ip_addr));
	ret += "源IP:";
	ret += QObject::tr("%1.%2.%3.%4").arg(s_ip_addr.byte1).arg(s_ip_addr.byte2).arg(s_ip_addr.byte3).arg(s_ip_addr.byte4);
    ret += "\n目的IP:";
	ret += QObject::tr("%1.%2.%3.%4").arg(d_ip_addr.byte1).arg(d_ip_addr.byte2).arg(d_ip_addr.byte3).arg(d_ip_addr.byte4);

//    struct ether_header *ethernet_protocol =

	u_char mac_string[6];
    memcpy(mac_string, arph->smac, sizeof(mac_string));
	char s_mac[28];
	sprintf(s_mac, "%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
    memcpy(mac_string, arph->dmac, sizeof(mac_string));
	char d_mac[28];
	sprintf(d_mac, "%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
    ret += "\n源MAC:";
	ret += s_mac;
    ret += "目的MAC:";
	ret += d_mac;

	return ret;

}

//QString parseHTTPPackage(const u_char* data){

//    QString ret;
//    ret+=parseIPPackage(data);




//}

QString parseTCPPackage(const u_char* data) {

    QString ret="";

    if(data == NULL){
        ret = "ERROR!!!!";
        return ret;
    }

	struct tcphdr *tcp_protocol;
	u_int16_t checksum;
    tcp_protocol = (struct tcphdr *) (data+sizeof(ether_header)+sizeof(ip_header));
	checksum = ntohs(tcp_protocol->check);
	ret += QObject::tr("源端口:%1\n").arg(ntohs(tcp_protocol->source_port));
	ret += QObject::tr("目的端口:%1\n").arg(ntohs(tcp_protocol->dest_port));
	ret += QObject::tr("SEQ:%1\n").arg(ntohl(tcp_protocol->seq));
	ret += QObject::tr("ACK SEQ:%1\n").arg(ntohl(tcp_protocol->ack_seq));
    ret += QObject::tr("TCP校验和:%1\n").arg(checksum);
    if (ntohs(tcp_protocol->source_port) == 80 || ntohs(tcp_protocol->dest_port) == 80||ntohs(tcp_protocol->source_port) == 443 || ntohs(tcp_protocol->dest_port) == 443)//http协议
        ret += "http data:\n\n"+QString::fromLatin1((char *)(data + sizeof(tcphdr)+sizeof(ether_header)+sizeof(ip_header)));

    return ret;
}

QString parseUDPPackage(const u_char* data) {

	QString ret;

	struct udphdr *udp_protocol;
	u_int16_t checksum;
    udp_protocol = (struct udphdr *) (data+sizeof(ether_header)+sizeof(ip_header));
	checksum = ntohs(udp_protocol->check);
	ret += QObject::tr("源端口:%1\n").arg(ntohs(udp_protocol->source_port));
	ret += QObject::tr("目的端口:%1\n").arg(ntohs(udp_protocol->dest_port));
	ret += QObject::tr("UDP数据包长度:%1\n").arg(ntohs(udp_protocol->len));
    ret += QObject::tr("UDP校验和:%1\n").arg(checksum);

	return ret;

}
