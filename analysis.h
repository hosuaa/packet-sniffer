#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

void analyse(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose, int no);
void checkIfSYN(void);
void checkIfARP(void);
void checkIfBlacklist(void);
void INTHandler(int sig);
#endif
