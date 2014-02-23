#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LENGTH (1 << 28)
#define NUM_ENTRIES 64
#define TABLE_SIZE (1 << 11)
#define MASK (TABLE_SIZE-1)

// Print the state.
void printState(char *message, uint32_t state[8]) {
    puts(message);
    for(uint32_t i = 0; i < 8; i++) {
        printf("%u ", state[i]);
    }
    printf("\n");
}

// Check to see if the state is already in the table.
static inline uint64_t stateInTable(uint32_t state[8], int32_t *hashTable, uint32_t *multHashes) {
    uint32_t mask = MASK;
    uint32_t addr = state[0] & mask;
    while(hashTable[addr] != -1) {
        if(!memcmp(state, multHashes + hashTable[addr], 32)) {
            return 1LL << (hashTable[addr]/8);
        }
        addr++;
        if(addr == TABLE_SIZE) {
            addr = 0;
        }
    }
    return 0;
}

// Add the state to the hash table.
static inline void addToTable(uint32_t state[8], int32_t hashTable[TABLE_SIZE],
        uint32_t multHashes[NUM_ENTRIES*8], uint32_t hashCount) {
    memcpy(multHashes + 8*hashCount, state, 32);
    uint32_t mask = MASK;
    uint32_t addr = state[0] & mask;
    while(hashTable[addr] != -1) {
        addr++;
        if(addr == TABLE_SIZE) {
            addr = 0;
        }
    }
    hashTable[addr] = 8*hashCount;
}

// Do low memory-bandwidth multplication hashing.
static void multHash(uint32_t state[8], uint64_t length, bool selfTest) {
    uint32_t multHashes[NUM_ENTRIES*8];
    int32_t hashTable[TABLE_SIZE];
    memset(multHashes, 0, NUM_ENTRIES*32);
    memset(hashTable, -1, TABLE_SIZE*4);
    uint64_t nextNewIndex = 1;
    uint32_t hashCount = 0;
    uint32_t futureState[8];
    if(selfTest) {
        memcpy(futureState, state, 32);
        multHash(futureState, 100, false);
        addToTable(futureState, hashTable, multHashes, hashCount);
        nextNewIndex <<= 1;
        hashCount++;
    }
    for(uint64_t i = 1; i < length; i++) {
        state[0] = (state[0]*(state[1] | 1)) ^ (state[2] >> 1);
        state[1] = (state[1]*(state[2] | 1)) ^ (state[3] >> 1);
        state[2] = (state[2]*(state[3] | 1)) ^ (state[4] >> 1);
        state[3] = (state[3]*(state[4] | 1)) ^ (state[5] >> 1);
        state[4] = (state[4]*(state[5] | 1)) ^ (state[6] >> 1);
        state[5] = (state[5]*(state[6] | 1)) ^ (state[7] >> 1);
        state[6] = (state[6]*(state[7] | 1)) ^ (state[0] >> 1);
        state[7] = (state[7]*(state[0] | 1)) ^ (state[1] >> 1);
        uint64_t count = stateInTable(state, hashTable, multHashes);
        if(count != 0) {
            printf("Found cycle! First time at %lu, second time at %lu, loop size:%lu\n", count, i,
                i - count);
            printState("", state);
            exit(1);
        }
        if(i == nextNewIndex) {
            addToTable(state, hashTable, multHashes, hashCount);
            nextNewIndex <<= 1;
            hashCount++;
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
        multHash(state, LENGTH, false);
        i++;
    }
}
