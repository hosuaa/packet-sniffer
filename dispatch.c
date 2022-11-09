#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include "analysis.h"
#include "queue.h"
#include <signal.h>
static struct queue work_queue; //dispatch() adds work to queue, worker threads pulls work from queue in work_thread()
static int queue_init=0; //flag to check if queue has been initialised (so it doesn't get initialised more than once)
static short ctrl_c=0; //flag to check if ctrl_c has been pressed
/* mutex lock required for the shared queue*/
pthread_mutex_t queue_mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond=PTHREAD_COND_INITIALIZER;
void* work_thread(void* arg) {
	if (queue_init==0) { //same as dispatch, but threads might begin work first so check
		create_queue(&work_queue);
		queue_init=1;
	}
	//packet information
	const struct pcap_pkthdr* header;
	const unsigned char* packet;
	int no;
	int verbose;
	//infinite loop (thread constantly waits for work)
	while(1) {
                pthread_mutex_lock(&queue_mutex); //lock so only 1 thread can pull work at once
		while(empty(&work_queue)) { //if empty no work in queue so wait
                        pthread_cond_wait(&queue_cond,&queue_mutex);
                }
		header=work_queue.head->data.header;
		packet=work_queue.head->data.packet;
		verbose=work_queue.head->data.verbose;
		no=work_queue.head->data.no;
		dequeue(&work_queue); //assign values from head of queue (get packet info) and dequeue
                pthread_mutex_unlock(&queue_mutex); //unlock for next thread
		//printf("analyzing packet number: %d\n", no); debug to check if all packets are being processed
                analyse(header, packet, verbose, no); //begin analysis

		if (ctrl_c) { //if this is 1 then ctrl_c was pressed so begin thread termination
			if (queue_init==1) {
				queue_init=0; //if the queue exists, destroy it and set the flag to 0 so no other thread can
				destroy_queue(&work_queue);
			}
			return (void*) NULL; //exit
		}
		signal(SIGINT, INTHandler); // INTHandler defined in sniff.c, called when ctrl_c is pressed
        }
        return (void*) NULL;

}

void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded
	if (queue_init==0) { //check if queue has already been initialised (it may have by one of the threads already)
                create_queue(&work_queue); // if not create the queue and set the flag to 1 so the queue will not be created again
                queue_init=1;
        }
	static int packetno=1; // packet counter for debugging purposes
	struct arg_struct args = {header, packet, verbose, packetno}; //packet info to be enqueued
	packetno++; //increment for next packet
	pthread_mutex_lock(&queue_mutex); // lock and enqueue the packet (locked so we don't enqueue and dequeue at the same time)
	enqueue(&work_queue,args);
        pthread_cond_broadcast(&queue_cond); //signal to waiting thread to collect work
        pthread_mutex_unlock(&queue_mutex);
}
