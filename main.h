#include "header/ethhdr.h"
#include "header/iphdr.h"
#include "header/tcphdr.h"
#include "kmp.h"

#define MAX_PATTERN_LEN 1024
#define BLOCK_MESSAGE "BLOCKED!"

#pragma pack(push, 1)
typedef struct TcpPacketHdr {
	EthHdr eth_;
	IpHdr ip_;
    TcpHdr tcp_;
} tcp_packet_hdr_t;
#pragma pack(pop)
