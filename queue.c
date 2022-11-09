#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

void create_queue(struct queue* q){ //creates a queue and returns its pointer
  q=(struct queue*)malloc(sizeof(struct queue));
  q->head=NULL;
  q->tail=NULL;
}

void destroy_queue(struct queue* q){  //destroys the queue and frees the memory
  while(!empty(q)){
    dequeue(q);
  }
  free(q);
}

int empty(struct queue* q) {
	return(q->head==NULL);
}
void enqueue(struct queue* q, struct arg_struct val) {
  struct element* elem=(struct element*)malloc(sizeof(struct element));
  elem->data = val; //equivalent to (*elem).data
  elem->next = NULL; // Really important to explicitly set this to null. Malloc does not zero memory
  if (empty(q)==1) {
  // Empty list, we need to append to head
    q->head=elem;
    q->tail=elem;
  } else {
    //List has some elements, find the end and append to that
    q->tail->next=elem;
    q->tail=elem;
  }

}
void dequeue(struct queue* q) { //dequeues a the head node
struct element *head_node;
  if(empty(q)){
    printf("Error: attempt to dequeue from an empty queue");
  }
  else{
    head_node=q->head;
    q->head=q->head->next;
    if(q->head==NULL)
      q->tail=NULL;
    free(head_node);
  }
}
