#pragma once

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <iostream>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>


    struct ethernetheader{
        uint8_t dhost[6];
        uint8_t shost[6];
        uint8_t type[2]; // arp : 0x0806,
    }; //14 bytes

    struct arpheader{
        uint8_t hdtype[2];
        uint8_t prttype[2];
        uint8_t hdadlen[1];
        uint8_t prtadlen[1];
        uint8_t opcode[2];
        uint8_t senderHW[6];
        uint8_t senderIP[4];
        uint8_t targetHW[6];
        uint8_t targetIP[4];

    }; //28bytes


int getMacAddress(char* dev, uint8_t mac[]) {
    struct ifreq ifr;
    int s;
    if ((s = socket(AF_INET, SOCK_STREAM,0)) < 0) {
        perror("socket");
        return -1;
    }

    strcpy(ifr.ifr_name, dev);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        return -1;
    }

    unsigned char *hwaddr = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    for(int i=0; i<6; i++) {
        mac[i] = hwaddr[i];
    }

    close(s);

    return 0;
}






void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");

}


