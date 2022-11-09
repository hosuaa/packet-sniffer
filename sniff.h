#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H
void endprogram(void);
void INTHandler(int sig);
void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);

#endif
