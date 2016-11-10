#include <iostream>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <netinet/in.h>


void usage() {
    printf("02_pcap <file>\n");
}

void ether_ntoa_pad(const ether_addr* addr, char *buf)
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr->ether_addr_octet[0], addr->ether_addr_octet[1],
            addr->ether_addr_octet[2], addr->ether_addr_octet[3],
            addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
}

void print_packet_info(const u_char *packet) {
    ether_header* eth_h;
    eth_h = (ether_header*) packet;
    ether_addr *saddr, *daddr;
    saddr = (ether_addr*) eth_h->ether_shost;
    daddr = (ether_addr*) eth_h->ether_dhost;
    char* saddrPretty = new char[6*2 + 5];
    char* daddrPretty = new char[6*2 + 5];
    ether_ntoa_pad(saddr, saddrPretty);
    ether_ntoa_pad(daddr, daddrPretty);
    printf("%s %s %#06x\n", daddrPretty, saddrPretty, ntohs(eth_h->ether_type));
    delete saddrPretty;
    delete daddrPretty;
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

    pcap_loop(data, 0, loop_callback, NULL);

    return 0;
}