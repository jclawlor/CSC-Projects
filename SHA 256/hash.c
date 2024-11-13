/** 
 * @file hash.c
 * @author jclawlor
 * Main file for the hash program
*/

#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>

/** Number of arguments if there is an input file */
#define ARGUMENTS 2

/**
 * main function for hash.c
 * @param argc num of arguments
 * @param argv arguments
 * @return 1 for failure 0 for success
*/
int main(int argc, char *argv[]) {
  FILE *fp;
  if (argc == ARGUMENTS) {
    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        perror(argv[1]);
        exit(EXIT_FAILURE);
    }
  }
  else if (argc > ARGUMENTS) {
    fprintf(stderr, "usage: hash [input_file]\n");
    exit(EXIT_FAILURE);
  }
  else if (argc < ARGUMENTS) {
    fp = stdin;
  }
  
  size_t size = 0;
  size_t capacity = BLOCK_SIZE;
  byte *input = (byte *)malloc(capacity);
  int count = 0;
  while ( (count = fread(input + size, 1, 1, fp)) > 0) {
    size += count;
    if (size == capacity) {
        capacity += BLOCK_SIZE;
        input = realloc(input, capacity);
    }
  }

  SHAState *state = makeState();
  update(state, input, size);

  word hashword[ HASH_WORDS ];
  digest(state, hashword);

  for (int i = 0; i < HASH_WORDS; i++) {
    printf("%08x", hashword[i]);
  }
  printf("\n");
  free(input);
  freeState(state);
  fclose(fp);

  exit(EXIT_SUCCESS);


}