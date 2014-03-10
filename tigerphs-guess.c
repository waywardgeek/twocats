/*
   TigerPHS main wrapper.

   Written in 2014 by Bill Cox <waywardgeek@gmail.com>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include "tigerphs.h"
#include "tigerphs-impl.h"

static void usage(char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, (char *)format, ap);
    va_end(ap);
    fprintf(stderr, "\nUsage: tigerphs-guess maxMemory maxTime\n");
    exit(1);
}

static uint32_t readuint32_t(char *paramName, char *arg) {
    char *endPtr;
    char *p = arg;
    uint32_t value = strtol(p, &endPtr, 0);
    if(*p == '\0' || *endPtr != '\0') {
        usage("Invalid integer for parameter %s", paramName);
    }
    return value;
}

// Find a good set of parameters for this machine based on a desired hashing time and
// maximum memory.  maxTime is in microseconds, and maxMem is in KiB.
void TigerPHS_GuessParameters(uint32_t maxTime, uint32_t maxMem, uint32_t maxParallelism, uint32_t *memSize,
        uint32_t *multiplies, uint32_t *parallelism, uint32_t *repetitions) {
    *repetitions = 1;
    *parallelism = TIGERPHS_PARALLELISM; // TODO: pick this automagically
    *multiplies = 0;
    *memSize = 1;
    uint8_t password[1] = {'\0'};
    uint8_t salt[1] = {'\0'};
    while(true) {
        clock_t start = clock();
        uint8_t buf[32];
        if(!TigerPHS_HashPassword(buf, 32, password, 1, salt, 1, *memSize, *multiplies,
                0, NULL, 0, TIGERPHS_BLOCKSIZE, TIGERPHS_SUBBLOCKSIZE, *parallelism, *repetitions, false)) {
            fprintf(stderr, "Memory hashing failed\n");
            exit(1);
        }
        clock_t end = clock();
        clock_t millis = (end - start) * 1000 / CLOCKS_PER_SEC;
        printf("Time: %lu\n", millis);
        if(millis > (1.25*maxTime)) {
            if(*multiplies == 0) {
                uint32_t newMillis;
                if(*multiplies == 0) {
                    do {
                        clock_t newStart = clock();
                        *multiplies += 1;
                        printf("Increasing multiplies to %u\n", *multiplies);
                        if(!TigerPHS_HashPassword(buf, 32, password, 1, salt, 1, *memSize, *multiplies,
                                0, NULL, 0, TIGERPHS_BLOCKSIZE, TIGERPHS_SUBBLOCKSIZE, *parallelism, *repetitions, false)) {
                            fprintf(stderr, "Memory hashing failed\n");
                            exit(1);
                        }
                        clock_t newEnd = clock();
                        newMillis = (newEnd - newStart) * 1000 / CLOCKS_PER_SEC;
                    } while(*multiplies != 8 && newMillis < 1.05*millis);
                }
            }
            return;
        }
        if(*memSize << 1 <= maxMem) {
            *memSize <<= 1;
            printf("Increasing memSize to %u\n", *memSize);
        } else if(*multiplies < 8) {
            *multiplies += 1;
            printf("Increasing multiplies to %u\n", *multiplies);
        } else {
            *repetitions <<= 1;
            printf("Increasing repetitions to %u\n", *repetitions);
        }
    }
}

int main(int argc, char **argv) {
    if(argc != 3) {
        usage("Incorrect number of parameters");
    }
    uint32_t maxMem = readuint32_t("maxMemory", argv[1]);
    uint32_t maxTime = readuint32_t("maxTime", argv[2]);
    uint32_t memSize, multiplies, parallelism, repetitions;

    TigerPHS_GuessParameters(maxTime, maxMem, 4, &memSize, &multiplies, &parallelism, &repetitions);
    printf("memSize:%u multiplies:%u parallelism:%u repetitions:%u\n", memSize, multiplies, parallelism, repetitions);
    printf("command: tigerphs -m %u -M %u -t %u -r %u\n", memSize, multiplies, parallelism, repetitions);
    return 0;
}
