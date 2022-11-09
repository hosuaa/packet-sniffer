#ifndef QUEUE_H_
#define QUEUE_H_
#include <pcap.h>
struct arg_struct {
    const struct pcap_pkthdr* header;
    const unsigned char* packet;
    int verbose;
    int no;
};
struct element {
	struct arg_struct data;
	struct element* next;
};
struct queue {
	struct element* head;
	struct element* tail;
};
void create_queue(struct queue* q);
int empty(struct queue* q);
void enqueue(struct queue* q, struct arg_struct val);
void dequeue(struct queue* q);
void destroy_queue(struct queue* q);
#endif
