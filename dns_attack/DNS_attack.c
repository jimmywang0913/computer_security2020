//DNS Query Program on Linux
//Author : Silver Moon (m00n.silv3r@gmail.com)
//Dated : 29/4/2009

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_UDP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/udp.h>      // struct udphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq

#include <errno.h>            // errno, perror()

// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define UDP_HDRLEN  8
char dns_servers[10][100];
int dns_server_count = 0;
//Types of DNS resource records :)

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

//Function Prototypes
void ngethostbyname(unsigned char*, int);
void ChangetoDnsNameFormat(unsigned char*, unsigned char*);
unsigned char* ReadName(unsigned char*, unsigned char*, int*);
void get_dns_servers();
uint16_t checksum(uint16_t*, int);
uint16_t udp4_checksum(struct ip, struct udphdr, uint8_t*, int);
char* allocate_strmem(int);
uint8_t* allocate_ustrmem(int);
int* allocate_intmem(int);


//DNS header structure
struct DNS_HEADER
{
	unsigned short id; // identification number

	unsigned char rd : 1; // recursion desired
	unsigned char tc : 1; // truncated message
	unsigned char aa : 1; // authoritive answer
	unsigned char opcode : 4; // purpose of message
	unsigned char qr : 1; // query/response flag

	unsigned char rcode : 4; // response code
	unsigned char cd : 1; // checking disabled
	unsigned char ad : 1; // authenticated data
	unsigned char z : 1; // its z! reserved
	unsigned char ra : 1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};
struct dnsadditional {
	//unsigned char      dnsa_name;
	unsigned short int dnsa_type;
	unsigned short int dnsa_udppayloadsize;
	unsigned short int dnsa_rccodenednsver;
	unsigned short int dnsa_z;
	unsigned short int dnsa_rdata;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
	unsigned char* name;
	struct R_DATA* resource;
	unsigned char* rdata;
};

//Structure of a Query
typedef struct
{
	unsigned char* name;
	struct QUESTION* ques;
} QUERY;

int main(int argc, char* argv[])
{
	unsigned char host[100] = "cs.nctu.edu.tw";
	//Get the DNS servers from the resolv.conf file
	get_dns_servers();	
	//Now get the ip of this hostname , A record
	//ngethostbyname(hostname, 28);
	int query_type = 255;
	unsigned char buf[65536], * qname, * reader;
	int i, j, stop;

	struct sockaddr_in a;

	struct RES_RECORD answers[20], auth[20], addit[20]; //the replies from the DNS server
	struct sockaddr_in dest;

	struct DNS_HEADER* dns = NULL;
	struct QUESTION* qinfo = NULL;

	//printf("Resolving %s", host);

	//s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
	int status, datalen, sd, * ip_flags;
	const int on = 1;
	char* interface, * target, * src_ip, * dst_ip;
	struct ip iphdr;
	struct udphdr udphdr;
	uint8_t* packet;
	struct addrinfo hints, * res;
	struct sockaddr_in* ipv4, sin,din;
	struct ifreq ifr;
	void* tmp;

	// Allocate memory for various arrays.
	packet = allocate_ustrmem(IP_MAXPACKET);
	interface = allocate_strmem(40);
	target = allocate_strmem(40);
	src_ip = allocate_strmem(INET_ADDRSTRLEN);
	dst_ip = allocate_strmem(INET_ADDRSTRLEN);
	ip_flags = allocate_intmem(4);

	// Interface to send packet through.
	//-指定需要傳送資料的網絡卡介面
	strcpy(interface, "enp0s3");

	// Submit request for a socket descriptor to look up interface.
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

	// Use ioctl() to look up interface index which we will use to
	// bind socket descriptor sd to specified interface with setsockopt() since
	// none of the other arguments of sendto() specify which interface to use.
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
	ioctl(sd, SIOCGIFINDEX, &ifr);
	close(sd);
	//printf("Index for interface %s is %i\n", interface, ifr.ifr_ifindex);

	// Source IPv4 address: you need to fill this out
	//-指定IP的源地址
	strcpy(src_ip, argv[1]);

	// Destination URL or IPv4 address: you need to fill this out
	//-指定IP的目的地址
	strcpy(target, argv[3]);

	// Fill out hints for getaddrinfo().
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;
	sin.sin_family = AF_INET;
	//din.sin_family = AF_INET;
	//sin.sin_addr.s_addr = inet_addr(argv[1]);
	//sin.sin_port = htons(atoi(argv[2]));
	//din.sin_addr.s_addr = inet_addr(argv[3]);
	//din.sin_port = htons(53);


	// Resolve target using getaddrinfo().
	if ((status = getaddrinfo(target, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(status));
		exit(EXIT_FAILURE);
	}

	ipv4 = (struct sockaddr_in*) res->ai_addr;
	tmp = &(ipv4->sin_addr);
	if (inet_ntop(AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
		status = errno;
		fprintf(stderr, "inet_ntop() failed.\nError message: %s", strerror(status));
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(res);
	//Set the DNS structure to standard queries
	dns = (struct DNS_HEADER*) & buf;

	dns->id = htons(0xECFD);
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = 1; //Recursion Desired
	dns->ra = 0; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = htons(1);

	//point to the query portion
	qname = (unsigned char*)& buf[sizeof(struct DNS_HEADER)];

	ChangetoDnsNameFormat(qname, host);
	qinfo = (struct QUESTION*) & buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

	qinfo->qtype = htons(query_type); //type of the query , A , MX , CNAME , NS etc
	qinfo->qclass = htons(1); //its internet (lol)
	struct dnsadditional* dnsa = (struct dnsadditional*) & buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 2) + sizeof(struct QUESTION)];
	dnsa->dnsa_type = htons(41);
	dnsa->dnsa_udppayloadsize = htons(4096);
	int payloadSiz = sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION) + sizeof(struct dnsadditional)+1;
	// IPv4 header
	// 構造ip報文
	// IPv4 header length (4 bits): Number of 32-bit words in header = 5
	iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);

	// Internet Protocol version (4 bits): IPv4
	iphdr.ip_v = 4;

	// Type of service (8 bits)
	iphdr.ip_tos = 16;

	// Total length of datagram (16 bits): IP header + UDP header + datalen
	iphdr.ip_len = htons(IP4_HDRLEN + UDP_HDRLEN + payloadSiz+ 1);

	// ID sequence number (16 bits): unused, since single datagram
	iphdr.ip_id = htons(0);

	// Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

	// Zero (1 bit)
	ip_flags[0] = 0;

	// Do not fragment flag (1 bit)
	ip_flags[1] = 1;

	// More fragments following flag (1 bit)
	ip_flags[2] = 0;

	// Fragmentation offset (13 bits)
	ip_flags[3] = 0;

	iphdr.ip_off = htons((ip_flags[0] << 15)
		+ (ip_flags[1] << 14)
		+ (ip_flags[2] << 13)
		+ ip_flags[3]);

	// Time-to-Live (8 bits): default to maximum value
	iphdr.ip_ttl = 255;

	// Transport layer protocol (8 bits): 17 for UDP
	iphdr.ip_p = IPPROTO_UDP;

	// Source IPv4 address (32 bits)
	if ((status = inet_pton(PF_INET, src_ip, &(iphdr.ip_src))) != 1) {
		fprintf(stderr, "inet_pton() failed.\nError message: %s", strerror(status));
		exit(EXIT_FAILURE);
	}

	// Destination IPv4 address (32 bits)
	if ((status = inet_pton(PF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
		fprintf(stderr, "inet_pton() failed.\nError message: %s", strerror(status));
		exit(EXIT_FAILURE);
	}

	// IPv4 header checksum (16 bits): set to 0 when calculating checksum
	iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum((uint16_t*)& iphdr, IP4_HDRLEN);

	// UDP header

	// Source port number (16 bits): pick a number
	//指定UDP報文源埠
	udphdr.source = htons(atoi(argv[2]));

	// Destination port number (16 bits): pick a number
	//指定UDP報文的目的埠
	udphdr.dest = htons(53);

	// Length of UDP datagram (16 bits): UDP header + UDP data
	udphdr.len = htons(UDP_HDRLEN + payloadSiz);

	// UDP checksum (16 bits)
	udphdr.check = udp4_checksum(iphdr, udphdr, buf, payloadSiz);

	// Prepare packet.

	// First part is an IPv4 header.
	memcpy(packet, &iphdr, IP4_HDRLEN * sizeof(uint8_t));

	// Next part of packet is upper layer protocol header.
	memcpy((packet + IP4_HDRLEN), &udphdr, UDP_HDRLEN * sizeof(uint8_t));

	// Finally, add the UDP data.
	// memcpy(packet + IP4_HDRLEN + UDP_HDRLEN, data, payloadSiz * sizeof(uint8_t));

	// The kernel is going to prepare layer 2 information (ethernet frame header) for us.
	// For that, we need to specify a destination for the kernel in order for it
	// to decide where to send the raw datagram. We fill in a struct in_addr with
	// the desired destination IP address, and pass this structure to the sendto() function.
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

	// Submit request for a raw socket descriptor.
	if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("socket() failed ");
		exit(EXIT_FAILURE);
	}

	// Set flag so socket expects us to provide IPv4 header.
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		perror("setsockopt() failed to set IP_HDRINCL ");
		exit(EXIT_FAILURE);
	}

	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(dns_servers[0]); //dns servers


	int hdrSiz = IP4_HDRLEN + UDP_HDRLEN;
	unsigned char actualPak[65536];
	memcpy(actualPak, packet, hdrSiz);
	memcpy(actualPak + hdrSiz, buf, payloadSiz);

	printf("\nSending Packet...");
	sendto(sd, (char*)actualPak, hdrSiz + payloadSiz, 0, (struct sockaddr*)& dest, sizeof(dest));
	printf("Done");
	printf("\nSending Packet...");
	sendto(sd, (char*)actualPak, hdrSiz + payloadSiz, 0, (struct sockaddr*)& dest, sizeof(dest));
	printf("Done");
	printf("\nSending Packet...");
	sendto(sd, (char*)actualPak, hdrSiz + payloadSiz, 0, (struct sockaddr*)& dest, sizeof(dest));
	printf("Done");
	printf("\n");
	//Receive the answer
	return 0;
}
/*
 *
 * */
u_char* ReadName(unsigned char* reader, unsigned char* buffer, int* count)
{
	unsigned char* name;
	unsigned int p = 0, jumped = 0, offset;
	int i, j;

	*count = 1;
	name = (unsigned char*)malloc(256);

	name[0] = '\0';

	//read the names in 3www6google3com format
	
	return name;
}
/*
 * This will convert www.google.com to 3www6google3com
 * got it :)
 * */
void ChangetoDnsNameFormat(unsigned char* dns, unsigned char* host)
{
	int lock = 0, i;
	strcat((char*)host, ".");

	for (i = 0; i < strlen((char*)host); i++)
	{
		if (host[i] == '.')
		{
			*dns++ = i - lock;
			for (; lock < i; lock++)
			{
				*dns++ = host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++ = '\0';
}
uint16_t
checksum(uint16_t * addr, int len)
{
	int nleft = len;
	int sum = 0;
	uint16_t* w = addr;
	uint16_t answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= sizeof(uint16_t);
	}

	if (nleft == 1) {
		*(uint8_t*)(&answer) = *(uint8_t*)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t
udp4_checksum(struct ip iphdr, struct udphdr udphdr, uint8_t * payload, int payloadlen)
{
	char buf[IP_MAXPACKET];
	char* ptr;
	int chksumlen = 0;
	int i;

	ptr = &buf[0];  // ptr points to beginning of buffer buf

	// Copy source IP address into buf (32 bits)
	memcpy(ptr, &iphdr.ip_src.s_addr, sizeof(iphdr.ip_src.s_addr));
	ptr += sizeof(iphdr.ip_src.s_addr);
	chksumlen += sizeof(iphdr.ip_src.s_addr);

	// Copy destination IP address into buf (32 bits)
	memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof(iphdr.ip_dst.s_addr));
	ptr += sizeof(iphdr.ip_dst.s_addr);
	chksumlen += sizeof(iphdr.ip_dst.s_addr);

	// Copy zero field to buf (8 bits)
	*ptr = 0; ptr++;
	chksumlen += 1;

	// Copy transport layer protocol to buf (8 bits)
	memcpy(ptr, &iphdr.ip_p, sizeof(iphdr.ip_p));
	ptr += sizeof(iphdr.ip_p);
	chksumlen += sizeof(iphdr.ip_p);

	// Copy UDP length to buf (16 bits)
	memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
	ptr += sizeof(udphdr.len);
	chksumlen += sizeof(udphdr.len);

	// Copy UDP source port to buf (16 bits)
	memcpy(ptr, &udphdr.source, sizeof(udphdr.source));
	ptr += sizeof(udphdr.source);
	chksumlen += sizeof(udphdr.source);

	// Copy UDP destination port to buf (16 bits)
	memcpy(ptr, &udphdr.dest, sizeof(udphdr.dest));
	ptr += sizeof(udphdr.dest);
	chksumlen += sizeof(udphdr.dest);

	// Copy UDP length again to buf (16 bits)
	memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
	ptr += sizeof(udphdr.len);
	chksumlen += sizeof(udphdr.len);

	// Copy UDP checksum to buf (16 bits)
	// Zero, since we don't know it yet
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 2;

	// Copy payload to buf
	memcpy(ptr, payload, payloadlen);
	ptr += payloadlen;
	chksumlen += payloadlen;

	// Pad to the next 16-bit boundary
	for (i = 0; i < payloadlen % 2; i++, ptr++) {
		*ptr = 0;
		ptr++;
		chksumlen++;
	}

	return checksum((uint16_t*)buf, chksumlen);
}

// Allocate memory for an array of chars.
char*
allocate_strmem(int len)
{
	void* tmp;

	if (len <= 0) {
		fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
		exit(EXIT_FAILURE);
	}

	tmp = (char*)malloc(len * sizeof(char));
	if (tmp != NULL) {
		memset(tmp, 0, len * sizeof(char));
		return (tmp);
	}
	else {
		fprintf(stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
		exit(EXIT_FAILURE);
	}
}

// Allocate memory for an array of unsigned chars.
uint8_t*
allocate_ustrmem(int len)
{
	void* tmp;

	if (len <= 0) {
		fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
		exit(EXIT_FAILURE);
	}

	tmp = (uint8_t*)malloc(len * sizeof(uint8_t));
	if (tmp != NULL) {
		memset(tmp, 0, len * sizeof(uint8_t));
		return (tmp);
	}
	else {
		fprintf(stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
		exit(EXIT_FAILURE);
	}
}

// Allocate memory for an array of ints.
int*
allocate_intmem(int len)
{
	void* tmp;

	if (len <= 0) {
		fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
		exit(EXIT_FAILURE);
	}

	tmp = (int*)malloc(len * sizeof(int));
	if (tmp != NULL) {
		memset(tmp, 0, len * sizeof(int));
		return (tmp);
	}
	else {
		fprintf(stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
		exit(EXIT_FAILURE);
	}
}
void get_dns_servers()
{
	FILE* fp;
	char line[200], * p;
	if ((fp = fopen("/etc/resolv.conf", "r")) == NULL)
	{
		printf("Failed opening /etc/resolv.conf file \n");
	}

	while (fgets(line, 200, fp))
	{
		if (line[0] == '#')
		{
			continue;
		}
		if (strncmp(line, "nameserver", 10) == 0)
		{
			p = strtok(line, " ");
			p = strtok(NULL, " ");

			//p now is the dns ip :)
			//????
		}
	}

	strcpy(dns_servers[0], "8.8.8.8");
	strcpy(dns_servers[1], "8.8.8.4");
}
