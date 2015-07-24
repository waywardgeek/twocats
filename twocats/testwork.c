#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "twocats.h"

static uint32_t numWorkers;
static uint32_t m_cost;
static uint8_t parallelism;

// Counters that keep track of how many iterations each worker has done.
static volatile uint32_t *counts;
static volatile uint32_t hashes;

// Do L3-cache intensive work in a regular manner, not SSE enabled.
static void *doWork(void *workerIDPtr) {
    uint32_t workerID = *(uint32_t *)workerIDPtr;
    uint32_t len = (1024u << m_cost)/(sizeof(uint32_t)*numWorkers);
    uint32_t *mem = calloc(len, sizeof(uint32_t));
    while(true) {
        for(uint32_t i = 0; i < len; i++) {
	    mem[i] ^= (mem[(i*i*i*i) & (len-1)] + i) * (i | 1);
        }
        counts[workerID]++;
    }
    return NULL;
}

// Start numWorker worker threads that do regular speed cache thrashing.
static void startWorkers(pthread_t *workerThreads, uint32_t numWorkers) {
    uint32_t *workerID = calloc(numWorkers, sizeof(uint32_t));
    for(uint32_t i = 0; i < numWorkers; i++) {
	workerID[i] = i;
        pthread_create(&workerThreads[i], NULL, doWork, workerID + i);
    }
}

// Run TwoCats over and over.
static void *runTwocats(void *ptr) {
    uint8_t password[8];
    memcpy(password, "password", 8);
    uint8_t salt[4];
    memcpy(salt, "salt", 4);
    uint8_t hash[64];
    while(true) {
	TwoCats_HashPasswordExtended(TWOCATS_BLAKE2B, hash,
            password, 8, salt, 4, NULL, 0, m_cost, m_cost, 0, TWOCATS_LANES,
            parallelism, TWOCATS_BLOCKSIZE, TWOCATS_BLOCKSIZE, 0, false, false);
        hashes++;
    }
    return NULL;
}

int main(int argc, char **argv) {
    if(argc != 5) {
        printf("Usage: %s numWorkers m_cost parallelism runTwocats\n", argv[0]);
        return 1;
    }
    numWorkers = atoi(argv[1]);
    m_cost = atoi(argv[2]);
    parallelism = atoi(argv[3]);
    bool hashMemory = atoi(argv[4]);
    pthread_t workerThreads[numWorkers];
    counts = calloc(numWorkers, sizeof(uint32_t));
    if(hashMemory) {
        hashes = 0;
        pthread_t twocatsThread;
        pthread_create(&twocatsThread, NULL, runTwocats, NULL);
    }
    if(numWorkers > 0) {
        startWorkers(workerThreads, numWorkers);
    }
    sleep(1);
    uint32_t totalWork = 0;
    for(uint32_t i = 0; i < numWorkers; i++) {
        totalWork += counts[i];
    }
    if(numWorkers > 0) {
        // The total work is how many times worker threads hash memory.  Since I divide the memory
        // among worker threads, I need to divide by the number of worker threads.
        totalWork /= numWorkers; // The total work is how many times worker threads hash memory
    }
    printf("Total work: %0u, total hashes: %u\n", totalWork, hashes);
    return 0;
}
