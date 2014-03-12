/*
   TwoCats main wrapper.

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
#include "twocats.h"
#include "twocats-impl.h"

static void usage(char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, (char *)format, ap);
    va_end(ap);
    fprintf(stderr, "\nUsage: twocats-phs hashlen password salt t_cost m_cost\n");
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
    if(argc != 6) {
        usage("Incorrect number of parameters");
    }
    uint32_t hashSize = readuint32_t("hashlen", argv[1]);
    uint32_t t_cost = readuint32_t("t_cost", argv[4]);
    uint32_t m_cost = readuint32_t("t_cost", argv[5]);
    char *password = argv[2];
    char *salt = argv[3];

    if(hashSize > 1024) {
        fprintf(stderr, "Hash size too big\n");
        return 1;
    }
    uint8_t hash[hashSize];
    if(PHS(hash, hashSize, (uint8_t *)password, strlen(password), (uint8_t *)salt, strlen(salt), t_cost, m_cost)) {
        fprintf(stderr, "Hashing failed.  Are the input parameters too big or small?\n");
        return 1;
    }
    printHex("", hash, hashSize);
    return 0;
}
