#include <stdio.h>	//For standard things
#include <stdlib.h>	//malloc
#include <string.h>	//memset
#include <netinet/ip_icmp.h>	//Provides declarations for icmp header
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>       
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <string.h>

void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char* , int);
void print_udp_packet(unsigned char * , int);
void print_icmp_packet(unsigned char* , int);
void PrintData (unsigned char* , int);

int sock_raw;
FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;

int start();
int stop();
int show();
int select_iface();
int stat();
int help();

int main(int argc, char* argv[])
{
	//solve();
	if(argc < 2)
	{
		printf("Error: you should write parametr\n");
		return 1;
	}
	if(argc == 2 && !strcmp(argv[1], "start")) start();
	if(argc == 2 && !strcmp(argv[1], "stop")) stop();
	if(argc == 4 && !strcmp(argv[1], "show") && !strcmp(argv[3], "count")) show();
	if(argc == 4 && !strcmp(argv[1], "select") && !strcmp(argv[2], "iface")) select_iface(argv[3]);
	if(argc == 3 && !strcmp(argv[1], "stat")) stat();
	if(argc == 2 && !strcmp(argv[1], "--help")) help();
	return 0;
}

int start()
{
	int saddr_size , data_size;
	struct sockaddr saddr;
	struct in_addr in;
	int count = 0;
	unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
	
	//logfile=fopen("log.txt","w");
	//if(logfile==NULL) printf("Unable to create file.");
	printf("Starting...\n");
	//Create a raw socket that shall sniff
	sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		return 1;
	}

    struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	FILE* system_input = fopen("system.txt", "r");
	char iface[10];
	fscanf(system_input, "%s", &iface);
	printf("%s\n", iface);
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), iface);
	if (setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
		printf("Problem with conection to interface\n");
		return 1;
	}

	while(1)
	{
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		//Now process the packet
		//ProcessPacket(buffer , data_size);
		printf("There is %d packets \n\r", ++count);

	}
	close(sock_raw);
	printf("Finished");
	return 0;
}

int stop()
{

}

int show()
{

}

int select_iface(char* iface)
{
	stop();
	FILE* system_input;
	system_input = fopen("system.txt", "w");
	fprintf(system_input, "%s\n", iface);
	fclose(system_input);
	start();
}

int help()
{

}

void ProcessPacket(unsigned char* buffer, int size)
{
	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr*)buffer;
	++total;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp;
			//PrintIcmpPacket(buffer,size);
			break;
		
		case 2:  //IGMP Protocol
			++igmp;
			break;
		
		case 6:  //TCP Protocol
			++tcp;
			print_tcp_packet(buffer , size);
			break;
		
		case 17: //UDP Protocol
			++udp;
			//print_udp_packet(buffer , size);
			break;
		
		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
	print_ip_header(buffer, size);
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d \n\r",tcp,udp,icmp,igmp,others,total);
}

void print_ip_header(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(logfile,"\n");
	fprintf(logfile,"IP Header\n");
	fprintf(logfile,"   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile,"   |-Identification    : %d\n",ntohs(iph->id));
	//fprintf(logfile,"   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	//fprintf(logfile,"   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	//fprintf(logfile,"   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	fprintf(logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile,"   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
			
	fprintf(logfile,"\n\n***********************TCP Packet*************************\n");	
		
	print_ip_header(Buffer,Size);
		
	fprintf(logfile,"\n");
	fprintf(logfile,"TCP Header\n");
	fprintf(logfile,"   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(logfile,"   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(logfile,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(logfile,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(logfile,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//fprintf(logfile,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(logfile,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(logfile,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(logfile,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(logfile,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(logfile,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(logfile,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(logfile,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(logfile,"   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(logfile,"   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(logfile,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(logfile,"\n");
	fprintf(logfile,"                        DATA Dump                         ");
	fprintf(logfile,"\n");
		
	fprintf(logfile,"IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile,"TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->doff*4);
		
	fprintf(logfile,"Data Payload\n");	
	PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
						
	fprintf(logfile,"\n###########################################################");
}

void PrintData (unsigned char* data , int Size)
{
	
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile,"         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logfile,"."); //otherwise print a dot
			}
			fprintf(logfile,"\n");
		} 
		
		if(i%16==0) fprintf(logfile,"   ");
			fprintf(logfile," %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces
			
			fprintf(logfile,"         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
				else fprintf(logfile,".");
			}
			fprintf(logfile,"\n");
		}
	}
}