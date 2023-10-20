#include "getAdapters.h"


vector<NetworkAdapter> getNetworkAdapters(){
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    vector<NetworkAdapter> adapters;

    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        qDebug() << "查找网卡失败!" << endl;
        return adapters;
    }

    for(pcap_if_t *d = alldevs; d!= nullptr; d = d->next)
    {

        NetworkAdapter adapter;
        bool has_ip = false;

        //不要loopback设备
        if (d->flags & PCAP_IF_LOOPBACK){
            continue;
        }

        if(d->description){
        //if(d->description && strstr(d->description, "Ethernet")){
            adapter.name = d->description;
        }else{
            continue;
        }

        for(pcap_addr_t* a = d->addresses; a != nullptr; a = a->next){
            if(a->addr->sa_family == AF_INET){
                //ip地址
                sockaddr_in* addr_in = (sockaddr_in*)a->addr;
                adapter.ip_address = inet_ntoa(addr_in->sin_addr);
                has_ip = true;
                //子网掩码
                sockaddr_in* mask_in = (sockaddr_in*)a->netmask;
                //网络字节顺序转换为主机字节顺序
                uint32_t netmask_host_order = ntohl(mask_in->sin_addr.s_addr);
                struct in_addr corrected_netmask;
                corrected_netmask.s_addr = netmask_host_order;
                adapter.netmask = inet_ntoa(corrected_netmask);
                break;
            }
        }

        if(!has_ip){
            continue;
        }

        adapters.push_back(adapter);
        qDebug() << QString::fromStdString(adapter.name +": "+adapter.ip_address+"("+adapter.netmask+")");
    }

    pcap_freealldevs(alldevs);

    return adapters;
}

