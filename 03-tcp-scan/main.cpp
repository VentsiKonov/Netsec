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

// Taken from
// http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html

u_int16_t ip_checksum(char* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data = vdata;
    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

void print_packet_info(const u_char *packet) {
    ether_header* eth_h = (ether_header*) packet;

    iphdr* ip_h = (iphdr*) (packet + sizeof(ether_header));

    unsigned int ihl_bytes = ip_h->ihl * 4;
    u_int16_t csum = ip_h->check;
    ip_h->check = 0;
    u_int16_t actual = ip_checksum((char*)ip_h, ihl_bytes);

    char saddrPretty[6*2 + 5] = {0};
    char daddrPretty[6*2 + 5] = {0};

    ether_ntoa_pad((ether_addr*) eth_h->ether_shost, saddrPretty);
    ether_ntoa_pad((ether_addr*) eth_h->ether_dhost, daddrPretty);

    if(actual != csum){
        printf("%s %s %#06x %s\n", daddrPretty, saddrPretty, ntohs(eth_h->ether_type), "bad_csum");
        return;
    }

    if(ip_h->protocol != IPPROTO_TCP) {
        return;
    }

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