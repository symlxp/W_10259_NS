#include "universaltools.h"

QVector<QMap<QString, QString>> getNetworkCardList()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char error_info[PCAP_ERRBUF_SIZE];

    pcap_findalldevs(&alldevs, error_info);

    QVector<QMap<QString, QString>> dev_info;

    for (d = alldevs; d != nullptr; d = d->next)
    {

        pcap_addr_t *a;

        QMap<QString, QString> ret;

        ret["name"] = d->name;

        if (d->description)
        {
            ret["description"] = d->description;
        }

        for (a = d->addresses; a; a = a->next)
        {

            switch (a->addr->sa_family)
            {
            case AF_INET:
                if (a->addr)
                {
                    ret["address"] = iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
                }
                if (a->netmask)
                {
                    ret["netmask"] = iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
                }
                if (a->broadaddr)
                {
                    ret["broadcast"] = iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr);
                }
                break;

            default:
                break;
            }
        }

        dev_info.push_back(ret);
    }

    pcap_freealldevs(alldevs);

    return dev_info;
}

char *iptos(u_long in)
{
    const int IPTOSBUFFERS = 12;

    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    _snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}
