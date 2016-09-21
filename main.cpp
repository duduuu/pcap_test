#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int main(int argc, char *argv[])
{
	pcap_t *handle;			// Session handle 
	char *dev;			// The device to sniff on 
	char errbuf[PCAP_ERRBUF_SIZE];	// Error string 
	bpf_u_int32 mask;		// Our mask 
	bpf_u_int32 net;		// Our IP 

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	// Find the properties for the device 
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	// Open the session in promiscuous mode
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	struct pcap_pkthdr *header;	// The header that pcap gives us
	const u_char *packet;		// The actual packet
	int res;
	struct ether_header *eth_hdr;
	struct iphdr *ip_hdr;
	struct tcphdr *tcp_hdr;
	u_char *payload;
	int length;

	while((res = pcap_next_ex(handle, &header, &packet)) >= 0)
	{
		if(res == 0) continue;	
		eth_hdr = (struct ether_header*)packet;
		printf("Source MAC : %s\n", ether_ntoa((struct ether_addr*)eth_hdr->ether_shost));
		printf("Destination MAC : %s\n", ether_ntoa((struct ether_addr*)eth_hdr->ether_dhost));

		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
		{
			ip_hdr = (struct iphdr*)(packet + 14);
			printf("Source IP : %s\n", inet_ntoa(*(struct in_addr*)&ip_hdr->saddr));
			printf("Destination IP : %s\n", inet_ntoa(*(struct in_addr*)&ip_hdr->daddr));

			if(ip_hdr->protocol == IPPROTO_TCP)
			{
				tcp_hdr = (struct tcphdr*)(packet + 14 + ip_hdr->ihl * 4);
				printf("Source Port : %d\n", ntohs(tcp_hdr->th_sport));
				printf("Destination Port : %d\n", ntohs(tcp_hdr->th_dport));
				length = header->len - (14 + ip_hdr->ihl * 4 + tcp_hdr->th_off * 4);
				if(length > 0)
				{
					payload = (u_char*)(packet + 14 + ip_hdr->ihl * 4 + tcp_hdr->th_off * 4) ;
					printf("Hexa demical value\n");
					for(int i = 0; i < length; i++)
					{
						printf("%02x ", (u_char)*(payload + i));
						if(i % 16 == 7) printf(" ");
						if(i % 16 == 15) printf("\n");
					}
					printf("\n");
				}
			}
		}		
	}
	return(0);
}















