/*
   TigerKDF main wrapper.

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
#include "tigerkdf.h"
#include "tigerkdf-impl.h"

static void usage(char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, (char *)format, ap);
    va_end(ap);
    fprintf(stderr, "\nUsage: tigerkdf-guess maxMemory maxTime\n");
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

int main(int argc, char **argv) {
    if(argc != 3) {
        usage("Incorrect number of parameters");
    }
    uint32_t maxMem = readuint32_t("maxMemory", argv[1]);
    uint32_t maxTime = readuint32_t("maxTime", argv[2]);
    uint32_t memSize, multiplies, parallelism, repetitions;

    TigerKDF_GuessParameters(maxTime, maxMem, 4, &memSize, &multiplies, &parallelism, &repetitions);
    printf("memSize:%u multiplies:%u parallelism:%u repetitions:%u\n", memSize, multiplies, parallelism, repetitions);
    return 0;
}
