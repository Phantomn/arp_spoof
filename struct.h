#pragma once
#include <stdint.h>

struct ethernet{
        uint8_t descMac[6];
        uint8_t srcMac[6];
        uint16_t ethType;
};
struct arp{
    uint16_t hwType;
    uint16_t procType;
    uint8_t hwSize;
    uint8_t procSize;
    uint16_t opcode;
    uint8_t sendMac[6];
    uint8_t sendIp[4];
    uint8_t targetMac[6];
    uint8_t targetIp[4];
};

struct ip{
        uint8_t version;
        uint8_t hdrLen;
        uint8_t dscp;
        uint16_t totLen;
        uint16_t ID;
        uint16_t flags;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t chksum;
        uint8_t srcIp[4];
        uint8_t destIp[4];
};
struct tcp{
        uint16_t srcPort;
        uint16_t destPort;
        uint32_t seqNum;
        uint8_t hdrLen;
        uint8_t flags[12];
        uint16_t winSize;
        uint16_t chksum;
        uint16_t urgPtr;
};
struct udp{
    uint16_t srcPort;
    uint16_t destPort;
    uint16_t len;
    uint16_t chkSum;
    uint8_t data[100];
};

struct http{
        uint8_t string[100];
};
