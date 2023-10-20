#include "snifferthread.h"

SnifferThread::SnifferThread(QMainWindow *w, string interface_name, QString filter)
{
    this->w = w;
    this->interface_name = interface_name;
    this->filter = filter;
    qDebug() << "线程创建，过滤器是：" << filter;
}


SnifferThread::~SnifferThread(){
    pcap_freealldevs(alldevs);
    pcap_close(this->handle);
    requestInterruption();
    quit();
    wait();
}


void SnifferThread::run(){

    //获取网卡列表
    if (pcap_findalldevs(&this->alldevs, errbuf) == -1) {
        qDebug() << "读取网卡失败!" << endl;
        return;
    }

    //找到网卡
    for(pcap_if_t *d = this->alldevs; d!= nullptr; d = d->next){
        if(d->description == interface_name){
             this->device = d;
             qDebug() << "选择网卡："  << this->device->description;
             break;
        }
    }

    //打开设备
    if((this->handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf)) == NULL){
        qDebug() << "无法打开网卡 " << device->name << " (" << device->description << ") : " << errbuf;
    }
    qDebug() << "打开网卡";

    //检查以太网环境
    if(pcap_datalink(this->handle) != DLT_EN10MB){
        qDebug() << "不支持非以太网环境";
    }

    //获取网卡掩码
    this->netmask = getNetmask();

    //设置过滤条件
    if(setFilter(filter) == false) {
        return;
    }else{
        //开始抓包
        qDebug() << "开始抓包";
        catchPacket();
    }
}


u_int SnifferThread::getNetmask() {
    u_int netmask;
    if(device->addresses != NULL) {
        netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr;
    } else {
        netmask = 0xffffff;
    }
    return netmask;
}


bool SnifferThread::setFilter(QString rule){
    if(rule == "default") {
        return true;
    }
    char *bpfFilter;
    QByteArray byteFilter =rule.toLatin1();
    bpfFilter = byteFilter.data();
    //设置bpf规则
    if(pcap_compile(this->handle, &bpf, bpfFilter, 1, netmask) < 0){
        qDebug() << "设置bpf规则失败";
        return false;
    }
    //设置过滤器
    if(pcap_setfilter(this->handle, &bpf) < 0){
        qDebug() << "设置过滤器失败";
        return false;
    }
    return true;
}


void SnifferThread::catchPacket(){
    int res;
    int index = 0;

    while((res = pcap_next_ex(handle, &header, &packet_data)) >= 0){

        if(res == 0){
            continue;
        }

        //获取数据包时
        struct tm now_time;
        char timestr[16];
        time_t local_time = header->ts.tv_sec;
        localtime_s(&now_time, &local_time);
        strftime(timestr, sizeof(timestr), "%H:%M:%S", &now_time);
        QString milliseconds = QString::number(header->ts.tv_usec).rightJustified(6, '0');
        QString timeStamp = QString(timestr) + "." + milliseconds;

        QStringList data = analysis_ethernet(header->len, packet_data);

        data.append(timeStamp);
        data.append(QString("%1").arg(header->len, 0, 10));

        emit sendData(index, data, header->len, packet_data);
        //qDebug() << index;
        index++;
    }
}


//struct EthernetHeader  {
//    uint8_t src_addr[6]; //源ip地址(6 byte)
//    uint8_t dest_addr[6]; //目的ip地址(6 byte)
//    uint16_t type; // 以太网类型(2 byte)：IPv4、ARP、IPv6
//};
QStringList SnifferThread::analysis_ethernet(uint packet_len, const u_char *packet_data){
    EthernetHeader *ethernetHeader;
    QStringList data;

    ethernetHeader = (EthernetHeader *)packet_data;
    ethernetHeader->type = ntohs(ethernetHeader->type);

    data << QString("Source: %1:%2:%3:%4:%5:%6")
            .arg(ethernetHeader->src_addr[0], 2, 16, QLatin1Char('0'))
            .arg(ethernetHeader->src_addr[1], 2, 16, QLatin1Char('0'))
            .arg(ethernetHeader->src_addr[2], 2, 16, QLatin1Char('0'))
            .arg(ethernetHeader->src_addr[3], 2, 16, QLatin1Char('0'))
            .arg(ethernetHeader->src_addr[4], 2, 16, QLatin1Char('0'))
            .arg(ethernetHeader->src_addr[5], 2, 16, QLatin1Char('0'))
         << QString("Destination: %1:%2:%3:%4:%5:%6")
            .arg(ethernetHeader->dest_addr[0], 2, 16, QLatin1Char('0'))
            .arg(ethernetHeader->dest_addr[1], 2, 16, QLatin1Char('0'))
            .arg(ethernetHeader->dest_addr[2], 2, 16, QLatin1Char('0'))
            .arg(ethernetHeader->dest_addr[3], 2, 16, QLatin1Char('0'))
            .arg(ethernetHeader->dest_addr[4], 2, 16, QLatin1Char('0'))
            .arg(ethernetHeader->dest_addr[5], 2, 16, QLatin1Char('0'));

    switch(ethernetHeader->type){
    case 0x0800: //IPv4
        data << QString("Type: IPv4 (0x%1)").arg(ethernetHeader->type, 4, 16, QLatin1Char('0'));
        data.append(analysis_ipv4(packet_len, packet_data));
        break;
    case 0x0806: //ARP
        data << QString("Type: ARP (0x%1)").arg(ethernetHeader->type, 4, 16, QLatin1Char('0'));
        data.append(analysis_arp(packet_data));
        break;
    case 0x86dd: //IPv6
        data <<QString("Type: IPv6 (0x%1)").arg(ethernetHeader->type, 4, 16, QLatin1Char('0'));
        data.append(analysis_ipv6(packet_len, packet_data));
        break;
    default:
        data << QString("Type: 0x%1").arg(ethernetHeader->type, 4, 16, QLatin1Char('0'));
        data.append("Ethernet II");
        break;
    }

    return data;
}


//struct ARPHeader {
//    uint16_t hardwareType; //硬件类型，Ethernet为1
//    uint16_t protocolType; //协议类型，IPv4为Ox0800
//    uint8_t hardwareSize; //硬件地址长度，Ethernet为6
//    uint8_t protocolSize; //协议地址长度，IPv4为4
//    uint16_t opcode; //操作码，1为请求、2为回复
//    uint8_t src_mac[6];
//    uint8_t src_ip[4];
//    uint8_t dest_mac[6];
//    uint8_t dest_ip[4];
//};
QStringList SnifferThread::analysis_arp(const u_char *packet_data){
    ARPHeader *arpHeader;
    QStringList data;

//    qDebug() << "开始分析ARP";
    arpHeader = (ARPHeader *)(packet_data + 14);
    arpHeader->hardwareType = ntohs(arpHeader->hardwareType);
    arpHeader->protocolType = ntohs(arpHeader->protocolType);
    arpHeader->opcode = ntohs(arpHeader->opcode);

    QString hardwareType;
    if(arpHeader->hardwareType == 0x1){
        hardwareType = "Hardware Type: Ethernet (0x1)";
    }else {
        hardwareType = QString("Hardware Type: 0x%1").arg(arpHeader->hardwareType, 0 ,16);
    }

    QString protocolType;
    switch(arpHeader->protocolType){
    case 0x0800: //IPv4
        protocolType = "Protocol Type: IPv4 (0x0800)";
        break;
    case 0x0806: //ARP
        protocolType = "Protocol Type: ARP (0x0806)";
        break;
    case 0x86dd: //IPv6
        protocolType = "Protocol Type: IPv6 (0x86dd)";
        break;
    default:
        protocolType = QString("Protocol Type: 0x%1").arg(arpHeader->protocolType, 4, 16, QLatin1Char('0'));
        break;
    }

    data << hardwareType
         << protocolType
         << QString("Hardware Size: %1").arg(arpHeader->hardwareSize, 0, 10)
         << QString("Protocol Size: %1").arg(arpHeader->protocolSize, 0, 10)
         << ((arpHeader->opcode == 0x1) ? QString("Opcode: request (1)") : QString("Opcode: response (2)"))
         << QString("Sender MAC address: %1:%2:%3:%4:%5:%6")
            .arg(arpHeader->src_mac[0], 2, 16, QLatin1Char('0'))
            .arg(arpHeader->src_mac[1], 2, 16, QLatin1Char('0'))
            .arg(arpHeader->src_mac[2], 2, 16, QLatin1Char('0'))
            .arg(arpHeader->src_mac[3], 2, 16, QLatin1Char('0'))
            .arg(arpHeader->src_mac[4], 2, 16, QLatin1Char('0'))
            .arg(arpHeader->src_mac[5], 2, 16, QLatin1Char('0'))
         << QString("Sender IP address: %1.%2.%3.%4")
            .arg(arpHeader->src_ip[0])
            .arg(arpHeader->src_ip[1])
            .arg(arpHeader->src_ip[2])
            .arg(arpHeader->src_ip[3])
         << QString("Target MAC address: %1:%2:%3:%4:%5:%6")
            .arg(arpHeader->dest_mac[0], 2, 16, QLatin1Char('0'))
            .arg(arpHeader->dest_mac[1], 2, 16, QLatin1Char('0'))
            .arg(arpHeader->dest_mac[2], 2, 16, QLatin1Char('0'))
            .arg(arpHeader->dest_mac[3], 2, 16, QLatin1Char('0'))
            .arg(arpHeader->dest_mac[4], 2, 16, QLatin1Char('0'))
            .arg(arpHeader->dest_mac[5], 2, 16, QLatin1Char('0'))
         << QString("Target IP address: %1.%2.%3.%4")
            .arg(arpHeader->dest_ip[0])
            .arg(arpHeader->dest_ip[1])
            .arg(arpHeader->dest_ip[2])
            .arg(arpHeader->dest_ip[3])
         << "ARP";
    return data;
}


//struct  IPv4Header {
//    uint8_t version:4;
//    uint8_t ihl:4;
//    uint8_t typeOfService;
//    uint16_t length;
//    uint16_t id;
//    uint16_t flagAndOffset;
//    uint8_t ttl;
//    uint8_t protocol; //上层协议含有TCP、UDP、ICMP等
//    uint16_t checksum;
//    uint8_t src_addr[4];
//    uint8_t dest_addr[4];
//    u_int option; //其他选项
//};
QStringList SnifferThread::analysis_ipv4(uint packet_len, const u_char *packet_data){
    IPv4Header *ipv4Header;
    QStringList data ;
    QStringList protocolData;

//    qDebug() << "开始分析IPv4";
    ipv4Header = (IPv4Header *)(packet_data + 14);
    ipv4Header->length = ntohs(ipv4Header->length);
    ipv4Header->id = ntohs(ipv4Header->id);
    ipv4Header->flagAndOffset = ntohs(ipv4Header->flagAndOffset);
    ipv4Header->checksum = ntohs(ipv4Header->checksum);

    uint offset = (ipv4Header->ver_ihl & 0xf) * 4;

    QString protocol;
    switch(ipv4Header->protocol){
    case 1: //ICMP
        //qDebug() << "ICMP";
        protocol = "ICMP";
        protocolData.append(analysis_icmp(packet_len, offset, packet_data));
        break;
    case 6: //TCP
        //qDebug() << "TCP";
        protocol = "TCP";
        protocolData.append(analysis_tcp(packet_len, offset, packet_data));
        break;
    case 17: //UDP
        //qDebug() << "UDP";
        protocol = "UDP";
        protocolData.append(analysis_udp(packet_len, offset, packet_data));
        break;
    default:
        protocol = "IPv4";
        break;
    }

    data << QString("Version: 4")
         << QString("Header Length: %1 bytes (%2)").arg(offset).arg(ipv4Header->ver_ihl & 0xf)
         << QString("Differentiated Services Field: 0x%1").arg(ipv4Header->typeOfService, 2, 16, QLatin1Char('0'))
         << QString("Total Length: %1").arg(ipv4Header->length)
         << QString("Identification: 0x%1").arg(ipv4Header->id, 4, 16, QLatin1Char('0'))
         << QString("Flags: 0x%1").arg(ipv4Header->flagAndOffset, 4, 16, QLatin1Char('0'))
         << QString("Time to live: %1").arg(ipv4Header->ttl, 0)
         << QString("Protocol: %1 (%2)").arg(protocol).arg(ipv4Header->protocol)
         << QString("Header Checksum: 0x%1").arg(ipv4Header->checksum, 4, 16, QLatin1Char('0'))
         << QString("Source: %1.%2.%3.%4")
            .arg(ipv4Header->src_addr[0])
            .arg(ipv4Header->src_addr[1])
            .arg(ipv4Header->src_addr[2])
            .arg(ipv4Header->src_addr[3])
         << QString("Destination: %1.%2.%3.%4")
            .arg(ipv4Header->dest_addr[0])
            .arg(ipv4Header->dest_addr[1])
            .arg(ipv4Header->dest_addr[2])
            .arg(ipv4Header->dest_addr[3]);
    data.append(protocolData);
    data.append(protocol);

    return data;
}


//struct IPv6Header {
//    u_int version:4, flowType:8, flowLabel:20;
//    uint16_t payloadLength; //有效负载长度
//    uint8_t nextHeader; //下一个头部的类型：TCP、UDP
//    uint8_t hopLimit; //ttl
//    uint16_t src_addr[8];
//    uint16_t dest_addr[8];
//};
QStringList SnifferThread::analysis_ipv6(uint packet_len, const u_char *packet_data){
    IPv6Header *ipv6Header;
    QStringList data;
    QStringList headerData;

//    qDebug() << "开始分析IPv6";
    ipv6Header = (IPv6Header *)(packet_data + 14);
    ipv6Header->payloadLength = ntohs(ipv6Header->payloadLength);

    QString nextHeader;
    switch(ipv6Header->nextHeader){
    case 0x06: //TCP
        //qDebug() << "TCPv6";
        nextHeader = "TCPv6";
        headerData.append(analysis_tcp(packet_len, 40, packet_data));
        break;
    case 0x11: //UDP
        //qDebug() << "UDPv6";
        nextHeader = "UDPv6";
        headerData.append(analysis_udp(packet_len, 40, packet_data));
        break;
    case 0x3a: //ICMPv6
        //qDebug() << "ICMPv6";
        nextHeader = "ICMPv6";
        headerData.append(analysis_icmp6(packet_len, 40, packet_data));
        break;
    default:
        nextHeader = "IPv6";
        break;
    }

    data << QString("Version: %1").arg(ipv6Header->version)
         << QString("Traffic Class: 0x%1").arg(ipv6Header->flowType, 2, 16, QLatin1Char('0'))
         << QString("Flow Label: %1").arg(ipv6Header->flowLabel, 5, 16, QLatin1Char('0'))
         << QString("Payload Length: %1").arg(ipv6Header->payloadLength)
         << QString("Next Header: %1 (%2)").arg(nextHeader).arg(ipv6Header->nextHeader)
         << QString("Hop Limit: %1").arg(ipv6Header->hopLimit)
         << QString("Source: %1:%2:%3:%4:%5:%6:%7:%8")
            .arg(ipv6Header->src_addr[0], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->src_addr[1], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->src_addr[2], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->src_addr[3], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->src_addr[4], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->src_addr[5], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->src_addr[6], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->src_addr[7], 4, 16, QLatin1Char('0'))
         << QString("Destination: %1:%2:%3:%4:%5:%6:%7:%8")
            .arg(ipv6Header->dest_addr[0], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->dest_addr[1], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->dest_addr[2], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->dest_addr[3], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->dest_addr[4], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->dest_addr[5], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->dest_addr[6], 4, 16, QLatin1Char('0'))
            .arg(ipv6Header->dest_addr[7], 4, 16, QLatin1Char('0'));
    data.append(headerData);
    data.append(nextHeader);

    return data;
}


//struct TCPHeader { //15
//    uint16_t src_port;
//    uint16_t dest_port;
//    u_int sequenceNum;
//    u_int ackNum;
//    uint16_t doff:4;
//    uint16_t res:4;
//    uint16_t cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, sym:1, fin:1;
//    uint16_t windowsize;
//    uint16_t checksum;
//    uint16_t urgentPtr;
//};
QStringList SnifferThread::analysis_tcp(uint packet_len, uint offset, const u_char *packet_data){
    TCPHeader *tcpHeader;
    QStringList data;
    QString flag;
    uint headerLength;
    uint dataLength;

    tcpHeader = (TCPHeader *)(packet_data + 14 + offset);
    tcpHeader->src_port = ntohs(tcpHeader->src_port);
    tcpHeader->dest_port = ntohs(tcpHeader->dest_port);
    tcpHeader->checksum = ntohs(tcpHeader->checksum);
    flag = QString("%1%2%3%4%5%6%7%8%9")
            .arg(tcpHeader->res, 4, 2, QLatin1Char('0'))
            .arg(tcpHeader->cwr, 1, 2)
            .arg(tcpHeader->ece, 1, 2)
            .arg(tcpHeader->urg, 1, 2)
            .arg(tcpHeader->ack, 1, 2)
            .arg(tcpHeader->psh, 1, 2)
            .arg(tcpHeader->rst, 1, 2)
            .arg(tcpHeader->syn, 1, 2)
            .arg(tcpHeader->fin, 1, 2);

    qDebug()<<"length"<<packet_len;
    headerLength = tcpHeader->doff * 4;
    dataLength = packet_len - 14 - offset - headerLength;

    data << QString("Source Port: %1").arg(tcpHeader->src_port)
         << QString("Destination Port: %1").arg(tcpHeader->dest_port)
         << QString("Sequence Number (raw): %1").arg(tcpHeader->sequenceNum)
         << QString("Acknowledgment Number (raw): %1").arg(tcpHeader->ackNum)
         << QString("Header Length: %1").arg(headerLength)
         << QString("Flags: 0x%1").arg(flag.toInt(nullptr, 2), 3, 16, QLatin1Char('0'))
         << QString("Window: %1").arg(tcpHeader->windowsize)
         << QString("Checksum: 0x%1").arg(tcpHeader->checksum, 4, 16, QLatin1Char('0'))
         << QString("Urgent Pointer: %1").arg(tcpHeader->urgentPtr)
         << QString("TCP payload (%1 bytes)").arg(dataLength);

    return data;
}


//struct UDPHeader {
//    uint16_t src_port;
//    uint16_t dest_port;
//    uint16_t length;
//    uint16_t checksum;
//};
QStringList SnifferThread::analysis_udp(uint packet_len, uint offset, const u_char *packet_data){
    UDPHeader *udpHeader;
    QStringList data;

    udpHeader = (UDPHeader *)(packet_data + 14 + offset);
    udpHeader->src_port = ntohs(udpHeader->src_port);
    udpHeader->dest_port = ntohs(udpHeader->dest_port);
    udpHeader->length = ntohs(udpHeader->length);
    udpHeader->checksum = ntohs(udpHeader->checksum);

    data << QString("Source Port: %1").arg(udpHeader->src_port)
         << QString("Destination Port: %1").arg(udpHeader->dest_port)
         << QString("Length: %1").arg(udpHeader->length)
         << QString("Checksum: 0x%1").arg(udpHeader->checksum, 4, 16, QLatin1Char('0'))
         << QString("UDP payload (%1 bytes)").arg(udpHeader->length - 8);

    return data;
}


//struct ICMPHeader {
//    uint8_t type;
//    uint8_t code;
//    uint16_t checksum;
//    uint16_t id;
//    uint16_t sequenceNum;
//};
QStringList SnifferThread::analysis_icmp(uint packet_len, uint offset, const u_char *packet_data){
    ICMPHeader *icmpHeader;
    QStringList data;

    icmpHeader = (ICMPHeader *)(packet_data + 14 + offset);
    icmpHeader->checksum = ntohs(icmpHeader->checksum);
    icmpHeader->id = ntohs(icmpHeader->id);

    QString type;
    switch(icmpHeader->type){
    case 0:
        type = "Echo (ping) Reply";
        break;
    case 8:
        type = "Echo (ping) Request";
        break;
    default:
        break;
    }

    data << QString("Type: %1 (" + type + ")").arg(icmpHeader->type)
         << QString("Code: %1").arg(icmpHeader->code)
         << QString("Checksum: 0x%1").arg(icmpHeader->checksum, 4, 16, QLatin1Char('0'))
         << QString("Identifier: %1 (0x%2)").arg(icmpHeader->id).arg(icmpHeader->id, 4, 16, QLatin1Char('0'))
         << QString("Sequence Number: %1 (0x%2)").arg(icmpHeader->sequenceNum).arg(icmpHeader->sequenceNum, 4, 16, QLatin1Char('0'))
         << QString("Data (%1 Bytes)").arg(packet_len - 14 - offset - 8);

    return data;
}


//struct ICMP6Header {
//    uint8_t type;
//    uint8_t code;
//    uint16_t checksum;
//};
QStringList SnifferThread::analysis_icmp6(uint packet_len, uint offset, const u_char *packet_data){
    ICMP6Header *icmp6Header;
    QStringList data;

    icmp6Header = (ICMP6Header *)(packet_data + 14 + offset);
    icmp6Header->checksum = ntohs(icmp6Header->checksum);

    QString type;
    switch(icmp6Header->type){
    case 130:
        type = " Multicast Listener Query";
        break;
    case 131:
        type = " Multicast Listener Report";
        break;
    case 132:
        type = " Multicast Listener Done";
        break;
    case 133:
        type = "Router Solicitation";
        break;
    case 134:
        type = "Router Advertisement";
        break;
    case 135:
        type = "Neighbour Solicitation";
        break;
    case 136:
        type = "Neighbour Advertisement";
        break;
    default:
        type = "ELSE";
        break;
    }

    data << QString("Type: " + type + " (%1)").arg(icmp6Header->type)
         << QString("Code: %1").arg(icmp6Header->code)
         << QString("Checksum: 0x%1").arg(icmp6Header->checksum, 4, 16, QLatin1Char('0'))
         << QString("Data (%1 Bytes)").arg(packet_len - 14 - offset - 8);

    return data;
}



