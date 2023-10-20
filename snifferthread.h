#ifndef SNIFFERTHREAD_H
#define SNIFFERTHREAD_H

#include "mypcap.h"
#include "structers.h"
#include <QDebug>
#include <QThread>
#include <QMainWindow>
#include <QByteArray>

using namespace std;


class SnifferThread : public QThread{
    Q_OBJECT

public:
    SnifferThread(QMainWindow *w, string interface_name, QString filter);
    ~SnifferThread();
    void run();

    void catchPacket();
    u_int getNetmask();
    bool setFilter(QString rule);
    QStringList analysis_ethernet(uint packet_len, const u_char *packet_data);
    QStringList analysis_arp(const u_char *packet_data);
    QStringList analysis_ipv4(uint packet_len, const u_char *packet_data);
    QStringList analysis_ipv6(uint packet_len, const u_char *packet_data);
    QStringList analysis_tcp(uint packet_len, uint offset, const u_char *packet_data);
    QStringList analysis_udp(uint packet_len, uint offset, const u_char *packet_data);
    QStringList analysis_icmp(uint packet_len, uint offset, const u_char *packet_data);
    QStringList analysis_icmp6(uint packet_len, uint offset, const u_char *packet_data);

    QMainWindow *w;

    string interface_name;
    QString filter;
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    struct pcap_pkthdr *header;
    const u_char *packet_data;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf;
    u_int netmask = 0xffffff;


signals:
    void sendData(int index, QStringList data, uint packet_len, const u_char *packet_data);

};

#endif // SNIFFERTHREAD_H
