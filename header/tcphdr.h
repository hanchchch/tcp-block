#pragma once

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)

struct TcpHdr final {
    uint16_t sport_;       /* source port */
    uint16_t dport_;       /* destination port */
    uint32_t seq_;          /* sequence number */
    uint32_t ack_;          /* acknowledgement number */

    uint8_t  x2_:4,       /* data offset */  
             off_:4;        /* (unused) */

    uint8_t  flags_;       /* control flags */

    uint16_t win_;         /* window */
    uint16_t sum_;         /* checksum */
    uint16_t urp_;         /* urgent pointer */

    typedef enum {
        FIN = 0x01,
        SYN = 0x02,
        RST = 0x04,
        PUSH = 0x08,
        ACK = 0x10,
		URG = 0x20,
		ECE = 0x40,
		CWR = 0x80
	} Flag;
};

#pragma pack(pop)
