#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string>
#include <errno.h>
#include <netinet/in.h>
#include <libnet.h>
#include <netinet/in.h>
#include <pcap.h>

#include "main.h"

char pattern[MAX_PATTERN_LEN];
int size_pattern;
Mac my_mac;

void usage() {
	puts("syntax : tcp-block <interface> <pattern>");
	puts("sample : tcp-block wlan0 \"Host: test.gilgil.net\"");
}

void dump(char* buf, int size) {
    for (int i=0; i<size; i++) {
        if (i%16 == 0) puts("");
        printf("%02hhx ", buf[i]);
    }
    puts("");
}

Mac get_my_mac(const char* dev) {
    struct ifreq ifr;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    char buf[32];

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        puts("Error");
        close(fd);
        exit(1);
    }
    else {
        close(fd);
        for (int i=0; i<MAC_ADDR_LEN; i++) 
            sprintf(&buf[i*3],"%02x:",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
        buf[MAC_ADDR_LEN*3 - 1]='\0';
        return Mac(buf);
    }
}

bool match_pattern(const u_char* packet, int size) {
    int size_data = size - sizeof(TcpPacketHdr);
    const u_char* data = packet + sizeof(TcpPacketHdr);

    return kmp((char*)data, size_data, pattern, size_pattern);
    //if (strstr(data, pattern) == nullptr) return false;
    //else return true;
}

void send_packet(pcap_t* handle, tcp_packet_hdr_t* packet, int size) {
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), size);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return;
    }
}

uint32_t wrapsum(uint16_t* buf, int size) {
    uint32_t cksum = 0;

    for(int i = 0; i < size/sizeof(uint16_t); i++) {  
        cksum += ntohs(buf[i]);
        cksum = (cksum & 0xffff) + (cksum >> 16);
    }
    return cksum;
}

uint16_t tcp_checksum(tcp_packet_hdr_t *tcphdr) {
    int size = tcphdr->tcp_.off_ * BIT32_IN_BYTE;
    uint16_t* pseudo_hdr = (uint16_t*)(new PseudoHdr(tcphdr->ip_.sip_, tcphdr->ip_.dip_, size));
    uint32_t cksum = 0;

    cksum += wrapsum(pseudo_hdr, sizeof(PseudoHdr));
    cksum += wrapsum((uint16_t*)&(tcphdr->tcp_), size);
    cksum = (cksum & 0xffff) + (cksum >> 16);

    delete pseudo_hdr;
    return htons((uint16_t)(~cksum));
}

uint16_t ip_checksum(tcp_packet_hdr_t *tcphdr) {
    int size = tcphdr->ip_.hl_ * BIT32_IN_BYTE;
    uint32_t cksum = 0;

    cksum += wrapsum((uint16_t*)&(tcphdr->ip_), size);
    cksum = (cksum & 0xffff) + (cksum >> 16);

    return htons((uint16_t)(~cksum));
}

void block(pcap_t* handle, tcp_packet_hdr_t* pk_f, tcp_packet_hdr_t* pk_b, int size) {
    int tcphdr_size = pk_f->tcp_.off_ * BIT32_IN_BYTE;
    int header_size = ETH_IP4_HEADER_LEN + tcphdr_size;
    int data_size = size - header_size;
    int new_size = size - data_size;

    (*pk_f).ip_.len_ = htons(new_size-sizeof(EthHdr));
    (*pk_f).ip_.sum_ = 0;
    (*pk_f).ip_.sum_ = ip_checksum(pk_f);
    (*pk_f).tcp_.seq_ += ntohl(data_size);
    (*pk_f).tcp_.flags_ = (TcpHdr::RST|TcpHdr::ACK);
    (*pk_f).tcp_.sum_ = 0;
    (*pk_f).tcp_.sum_ = tcp_checksum(pk_f);
	send_packet(handle, pk_f, new_size);

    //(*packet).tcp_.seq_ += ntohs((*packet).ip_.len_);
    //(*packet).tcp_.flags_ = TcpHdr::FIN;
    //strncpy(((char*)packet)+sizeof(TcpPacketHdr), BLOCK_MESSAGE, sizeof(BLOCK_MESSAGE));

	//send_packet(handle, pk_b, sizeof(TcpPacketHdr)+sizeof(BLOCK_MESSAGE));
}


void handle_packet(pcap_t* handle, const u_char* packet, int size) {
    if (!match_pattern(packet, size)) return;
    puts("matched");

    u_char* pk_f = (u_char*)malloc(sizeof(TcpPacketHdr));
    u_char* pk_b = (u_char*)malloc(sizeof(TcpPacketHdr)+sizeof(BLOCK_MESSAGE));

    memcpy(pk_f, packet, sizeof(TcpPacketHdr));
    memcpy(pk_b, packet, sizeof(TcpPacketHdr));

    block(handle, (tcp_packet_hdr_t*)pk_f, (tcp_packet_hdr_t*)pk_b, size);

    free(pk_f);
    free(pk_b);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    size_pattern = (int)strlen(argv[2]);
    strncpy(pattern, argv[2], size_pattern);

    my_mac = get_my_mac(dev);

    printf("%s\n", pattern);
    printf("%d\n", size_pattern);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        printf("%d cap\n", header->caplen);
        handle_packet(handle, packet, header->caplen);
    }

    pcap_close(handle);
}
