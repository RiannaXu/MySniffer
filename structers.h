#ifndef STRUCTERS_H
#define STRUCTERS_H

#include "mypcap.h"

#include <string>

using namespace std;

struct NetworkAdapter {
    string name;
    string ip_address;
    string netmask;
};

struct EthernetHeader  {
    u_char src_addr[6]; //源ip地址(6 byte)
    u_char dest_addr[6]; //目的ip地址(6 byte)
    u_short type; // 以太网类型(2 byte)：IPv4、ARP、IPv6
};

struct  IPv4Header {
    u_char ver_ihl;
    u_char typeOfService;
    u_short length;
    u_short id;
    u_short flagAndOffset;
    u_char ttl;
    u_char protocol; //上层协议含有TCP、UDP、ICMP等
    u_short checksum;
    u_char src_addr[4];
    u_char dest_addr[4];
    u_int option; //其他选项
};

struct IPv6Header {
    u_int version:4, flowType:8, flowLabel:20;
    u_short payloadLength; //有效负载长度
    u_char nextHeader; //下一个头部的类型：TCP、UDP
    u_char hopLimit; //ttl
    u_short src_addr[8];
    u_short dest_addr[8];
};

struct ARPHeader {
    u_short hardwareType; //硬件类型，Ethernet为1
    u_short protocolType; //协议类型，IPv4为Ox0800
    u_char hardwareSize; //硬件地址长度，Ethernet为6
    u_char protocolSize; //协议地址长度，IPv4为4
    u_short opcode; //操作码，1为请求、2为回复
    u_char src_mac[6];
    u_char src_ip[4];
    u_char dest_mac[6];
    u_char dest_ip[4];
};

struct TCPHeader { //15
    u_short src_port;
    u_short dest_port;
    u_int sequenceNum;
    u_int ackNum;
    u_short doff:4;
    u_short res:4;
    u_short cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
    u_short windowsize;
    u_short checksum;
    u_short urgentPtr;
    u_int option; //其他选项
};

struct UDPHeader {
    u_short src_port;
    u_short dest_port;
    u_short length;
    u_short checksum;
};

struct ICMPHeader {
    u_char type;
    u_char code;
    u_short checksum;
    u_short id;
    u_short sequenceNum;
};

struct ICMP6Header {
    u_char type;
    u_char code;
    u_short checksum;
};

struct packetData {
    int len;
    const u_char *packet_data;
};


#endif // STRUCTERS_H
