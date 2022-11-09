
#include <stdio.h>
#include <stdlib.h>

#include "darray.h"

struct darray;

void freeArray(darray* a) {// free dynamic array
	int i=0;
	for (i=0; i<a->used; i++) {
		free(a->array[i]); //lop through every element of array and free it
	}
  free(a->array); //free array
  a->used = a->size = 0; //set variables to defaults
}
void initArray(darray* a, size_t initialSize) { //initialise dynamic array 
  if (a->array!=NULL) { //if already been initialised skip
  	return;
  }
  char** tmp = malloc(initialSize * sizeof(char*)); //check return value of malloc
  if (tmp==NULL) {
  	printf("Failed malloc\n");
	free(tmp);
  	exit(1);
  }
  a->array = tmp;
  a->used = 0; //0 used since just initialsed
  a->size = initialSize; //current total size
}
void insertArray(darray* a, char* element) {// insert to array
  if (a->used == a->size) { //if its full
    a->size *= a->size; //increase total size
    char** tmp = realloc(a->array, a->size * a->size);// realloc with new size and check return value of realloc
							//important so we don't lose the pointer with the original array
    if (tmp==NULL) {
    	printf("Failed realloc\n");
    	free(tmp);
    	freeArray(a);
    	exit(1);
    }
    a->array = tmp;
  }
  a->array[a->used++] = element; //set element and increment used
}

void printArray(darray* a) { //print array for testing
	int i=0;
	for (i=0; i<a->used; i++) {
		printf("%s\n", a->array[i]);
	}
}
