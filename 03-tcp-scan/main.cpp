#include <iostream>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cstring>

void usage() {
    printf("03-tcp-scan <file>\n");
}

void ether_ntoa_pad(const ether_addr* addr, char *buf)
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr->ether_addr_octet[0], addr->ether_addr_octet[1],
            addr->ether_addr_octet[2], addr->ether_addr_octet[3],
            addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
}

void print_packet_info(const u_char *packet) {
    ether_header* eth_h = (ether_header*) packet;

    iphdr* ip_h = (iphdr*) (packet + sizeof(ether_header));
    if(ip_h->protocol != IPPROTO_TCP) {
        return;
    }

    unsigned int ihl_bytes = ip_h->ihl * 4;
    tcphdr* tcp_h = (tcphdr*) (packet + sizeof(ether_header) + ihl_bytes);

    char* packetType;
    u_int8_t xmasMask = TH_FIN | TH_URG | TH_PUSH;

    if (tcp_h->th_flags == 0){
        packetType = strdup("Null");
    }
    else if (tcp_h->th_flags & xmasMask){
        packetType = strdup("Xmas");
    }
    else {
        return;
    }

    char* saddrPretty = new char[6*2 + 5];
    char* daddrPretty = new char[6*2 + 5];

    ether_ntoa_pad((ether_addr*) eth_h->ether_shost, saddrPretty);
    ether_ntoa_pad((ether_addr*) eth_h->ether_dhost, daddrPretty);

    char* sipPretty = strdup(inet_ntoa(*(in_addr*)&ip_h->saddr));
    char* dipPretty = strdup(inet_ntoa(*(in_addr*)&ip_h->daddr));

    printf("%s %s %#06x %s %s %d %d %d %s\n",
           daddrPretty,
           saddrPretty,
           ntohs(eth_h->ether_type),
           sipPretty,
           dipPretty,
           ip_h->protocol,
           ntohs(tcp_h->source),
           ntohs(tcp_h->dest),
           packetType
    );
    delete saddrPretty;
    delete daddrPretty;
    delete sipPretty;
    delete dipPretty;
    delete packetType;
}

void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *body)
{
    print_packet_info(body);
    return;
}

int main(int argc, char** argv) {
    if(argc < 2){
        usage();
        return 1;
    }

    const char* filename = argv[1];
    char error_buffer[PCAP_ERRBUF_SIZE];

    pcap_t* data = pcap_open_offline(filename, error_buffer);
    if (data == NULL){
        printf("Error: %s", error_buffer);
        return 1;
    }

    pcap_loop(data, 0, loop_callback, NULL);

    return 0;
}