#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Print the state.
void printState(char *message, uint32_t state[8]) {
    puts(message);
    for(uint32_t i = 0; i < 8; i++) {
        printf("%u ", state[i]);
    }
    printf("\n");
}

// Do low memory-bandwidth multplication hashing.
static void multHash(uint32_t state[8]) {
    uint32_t target = rand() | 1;
    uint32_t v = 1;
    uint32_t oddState[8];
    for(uint32_t i = 0; i < 8; i++) {
        oddState[i] = state[i] | 1;
    }
    for(uint64_t i = 1; true; i++) {
        for(uint32_t j = 0; j < 8; j++) {
            v *= oddState[j];
            v ^= oddState[(j+4)&7];
        }
        oddState[i&7] += (v >> 8) & ~1;
        //printf("v:%u\n", v);
        if(v == target) {
            printf("Found cycle! Loop size:%lu\n", i);
            printState("", oddState);
            return;
        }
    }
}


int main() {
    uint32_t i = 0;
    while(true) {
        printf("%i\n", i);
        uint32_t state[8];
        for(uint32_t i = 0; i < 8; i++) {
            state[i] = rand();
        }
        multHash(state);
        i++;
    }
}
