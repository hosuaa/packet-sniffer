#ifndef DARRAY_H_
#define DARRAY_H_

typedef struct darray {
  char **array;
  size_t used;
  size_t size;
} darray;

void freeArray(darray* a);
void initArray(darray* a, size_t initalSize);
void insertArray(darray* a, char* element);
void printArray(darray* a);

#endif
