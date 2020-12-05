#include "header/ethhdr.h"
#include "header/iphdr.h"
#include "header/tcphdr.h"
#include "kmp.h"

#define MAX_PATTERN_LEN 1024
#define BLOCK_MESSAGE "BLOCKED!"
#define ETH_IP4_HEADER_LEN 34
#define BIT32_IN_BYTE 4
#define MAC_ADDR_LEN 6
#define TCP_PROTO_NUM 6

#pragma pack(push, 1)
typedef struct TcpPacketHdr {
	EthHdr eth_;
	IpHdr ip_;
    TcpHdr tcp_;
} tcp_packet_hdr_t;
#pragma pack(pop)

struct PseudoHdr final{
    Ip sip_;
    Ip dip_;
    uint8_t x2_;
    uint8_t  p_;
    uint16_t tcplen_;

    PseudoHdr(Ip sip, Ip dip, uint16_t tcplen) : sip_(sip), dip_(dip), x2_(0), p_(TCP_PROTO_NUM), tcplen_(ntohs(tcplen)){};
};