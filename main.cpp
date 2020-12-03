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
int size_patten;

void usage() {
	puts("syntax : tcp-block <interface> <pattern>");
	puts("sample : tcp-block wlan0 \"Host: test.gilgil.net\"");
}

bool match_pattern(char* packet, int size) {
    int size_data = size - sizeof(TcpPacketHdr);
    char* data = packet + sizeof(TcpPacketHdr);

    return kmp(data, size_data, pattern, size_patten);
}

void send_packet(pcap_t* handle, tcp_packet_hdr_t* packet, int size) {
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), size);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return;
    }
}

void block(pcap_t* handle, tcp_packet_hdr_t* packet_f, tcp_packet_hdr_t* packet_b, int size){
    (*packet_f).tcp_.seq_ += ntohs((*packet_f).ip_.len_);
    (*packet_f).tcp_.flags_ = TcpHdr::RST;

	send_packet(handle, packet_f, size);

    (*packet_b).tcp_.seq_ += ntohs((*packet_b).ip_.len_);
    (*packet_b).tcp_.flags_ = TcpHdr::FIN;
    strncpy(((char*)packet_b)+sizeof(TcpPacketHdr), BLOCK_MESSAGE, sizeof(BLOCK_MESSAGE));

	send_packet(handle, packet_b, sizeof(TcpPacketHdr)+sizeof(BLOCK_MESSAGE));
}


void handle_packet(pcap_t* handle, char* packet, int size) {
    if (!match_pattern(packet, size)) return;

    char* pk_forward = (char*)malloc(size);
    char* pk_backward = (char*)malloc(size);

    memcpy(pk_forward, packet, size);
    memcpy(pk_backward, packet, sizeof(TcpPacketHdr));

    block(handle, (tcp_packet_hdr_t*)pk_forward, (tcp_packet_hdr_t*)pk_backward, size);
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

    size_patten = (int)strlen(argv[2]);
    strncpy(pattern, argv[2], size_patten);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        handle_packet(handle, (char*)packet, header->caplen);
    }

    pcap_close(handle);
}
