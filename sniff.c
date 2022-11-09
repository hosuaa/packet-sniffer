#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#include "analysis.h"
#include "dispatch.h"
#include <signal.h>
#include <pthread.h>
static const unsigned short THREADNUM=3; //constant for number of threads (e.g 3)
pthread_t threads[3]; //array of threads - cant use THREADNUM here have to use 3
void endprogram(void) { //called when ctrl_c is pressed
		int i=0;
		for (i=0; i<THREADNUM; i++) {
			pthread_kill(threads[i], SIGINT); //loop through all threads and send SIGINT to them (as if they pressed ctrl_c) so they can end
		}
		checkIfSYN(); //check if SYN attack  is likely
		checkIfARP(); //check if ARP cache poisoning likely
		checkIfBlacklist(); //check how many URL blacklist violation
		exit(0); //threads have ended, all information output, safe to exit
}
void INTHandler(int sig) { //signal handler called when ctrl_c is pressed
        if (sig == SIGINT) {
                endprogram(); //begin ending the program
        }
}
void process(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
	int verbose = atoi((char*)user); //convert passed argument back to verbose
	if (verbose) {
		dump(packet, header->len); //as implemented
	}
	dispatch(header, packet, verbose); //send packet for processing
	signal(SIGINT, INTHandler); //call INTHandler when SIGINT (CTRL_C) is pressed
}
// Application main sniffing loop
void sniff(char *interface, int verbose) {
  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  	int i=0;
  	for (i=0; i<THREADNUM; i++)  { //create threads and begin work (work_thread defined in dispatch.c)
        	printf("Creating thread %d\n", i);
        	pthread_create(&threads[i], NULL, &work_thread, NULL);
  	}
	pcap_loop(pcap_handle,-1,process,(u_char*)&verbose); //efficient implementation of capturing packets using pcap_loop. process is callback function, -1 so it captures packets indefinitely
}
// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
