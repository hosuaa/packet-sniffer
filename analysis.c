#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include "darray.h"
#include <pthread.h>
pthread_mutex_t global_mutex; //mutex lock to avoid race conditions for multithread
//void INTHandler(int);
static darray saddrs; //dynamic array which stores IP addresses of SYN packets
static unsigned long arpreply=0; //counter of ARP responses
static unsigned long blacklist=0; //counter of URL blacklist violations
void checkIfSYN() {
        int i=0,unique=0;
        for (i=0;i<saddrs.used;i++) { //checks for each IP if it is unique - runs in O(n^2)
                int j=0;
                for (j=0;j<i;j++) { //compares each IP against every other IP
                        if (strcmp(saddrs.array[i],saddrs.array[j])==0) { //if theyre equal its not unique so go to next I{
                                break;
                        }
                }
                if (i==j) { //checked every IP so unique
                        unique++;
                }
        }
        if (unique>100) { //large amount of unique SYN packets detected (I chose 100)
		printf("%ld SYN packets detected from %d unique IP(s) (SYN attack)\n", saddrs.used, unique);
	} else {
		printf("%ld SYN packets detected from %d unique IP(s) (SYN attack unlikely)\n", saddrs.used, unique);
	}
	freeArray(&saddrs); //free array since program is ending
}
void checkIfARP() {
	printf("%ld ARP responses (cache poisoning)\n", arpreply); //output all ARP responses detected
}
void checkIfBlacklist() {
	printf("%ld URL Blacklist violations\n", blacklist); //output all URL blacklist violations detected
}

void analyse(const struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose, int no) {
	initArray(&saddrs, 100); //initalise dynamic array with 100 elements
	packet+=14;// increment past ethernet header
	struct ether_arp* arp_h=(struct ether_arp*)(packet); //arp header
	unsigned short op = ntohs(arp_h->arp_op); //check ARP operation
	if (op==2) { //2 means ARP response
		pthread_mutex_lock(&global_mutex); //arpreply is global so lock it to avoid race condition
		arpreply++;
		pthread_mutex_unlock(&global_mutex);
	}
	struct ip* ip_h=(struct ip*)(packet); //ip header
	unsigned short iphlen = 4*ip_h->ip_hl; //ip header length
	packet+=iphlen; //increment to TCP header
	struct tcphdr* tcp_h=(struct tcphdr*)(packet);
        if ((tcp_h->syn==1)&&(tcp_h->fin==0)&&(tcp_h->rst==0)&&(tcp_h->psh==0)&&(tcp_h->ack==0)&&(tcp_h->urg==0)) { //if SYN packet
		pthread_mutex_lock(&global_mutex); //malloc is not threadsafe so lock
		char* saddr = malloc(strlen(inet_ntoa(ip_h->ip_src))+1); //inet_ntoa turns ip_src into a 4 byte string, malloc so we can store the IP
		pthread_mutex_unlock(&global_mutex);
		strcpy(saddr,inet_ntoa(ip_h->ip_src)); //copy ip_src into saddr
		pthread_mutex_lock(&global_mutex); //lock since saddrs is global
		insertArray(&saddrs, saddr);
		pthread_mutex_unlock(&global_mutex);
        }

	unsigned short dport = ntohs(tcp_h->th_dport); //destination port : ntohs used since th_dport is a short
	if (dport==80) { //HTTP
		unsigned short tcphlen = 4*tcp_h->doff;
		packet+=tcphlen;//increment past TCP to payload where URL is stored
		pthread_mutex_lock(&global_mutex);
		char* start=malloc(100*sizeof(char));
		start=strstr((char*)packet, "Host: "); //strstr is not threadsafe
		pthread_mutex_unlock(&global_mutex);
		if (start!=NULL) { //if a URL was found
			unsigned int c=0; start+=6; //start points to beginning of URL but that begins with "Host: " which is 6 bytes long so increment by 6 bytes
			while (*start!='\r') { //while the character pointed to by the url pointer is not \r (the first character after the end of the url)
				start++; c++; //increment to next character and store how many characters we have passed
			}
			start-=c; //go backwards the amount of characters passed (start will point to first 'w' of www. etc
			char* url=malloc(c*sizeof(char)+1); strncpy(url, start, c); //copy c bytes from start into url - url will contain url
			char* blacklistedDomains[] = {"www.google.co.uk", "www.bbc.com"}; //list of blacklisted domains
			unsigned int i=0;
			unsigned int noOfBDomains = sizeof(blacklistedDomains)/sizeof(blacklistedDomains[0]); //blacklistedDomains.length
			for (i=0; i<noOfBDomains; i++) {
				if (strcmp(url,blacklistedDomains[i])==0) {//check URL against every blacklisted domain, if equal output
					pthread_mutex_lock(&global_mutex); //lock so 2 threads cant output this at once and global variable blacklist
					printf("======================================\nBlacklisted URL violation detected\n");
                			printf("Source IP address: %s\n", inet_ntoa(ip_h->ip_src));
                			printf("Destination IP address: %s\n", inet_ntoa(ip_h->ip_dst));
                			printf("======================================\n");
                			blacklist++; //increment counter
					pthread_mutex_unlock(&global_mutex);
					break;
				}
			}
		} else {
			//printf("URL not found\n");
		}

	}
}
