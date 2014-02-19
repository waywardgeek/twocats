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
    fprintf(stderr, "\nUsage: tigerkdf-test [OPTIONS]\n"
        "    -h hashSize     -- The output derived key length in bytes\n"
        "    -p password     -- Set the password to hash\n"
        "    -s salt         -- Set the salt.  Salt must be in hexidecimal\n"
        "    -g garlic       -- Multiplies memory and CPU work by 2^garlic\n"
        "    -m memorySize   -- The amount of memory to use in KB\n"
        "    -M multipliesPerKB -- The number of sequential multiplies to execute per\n"
        "                       kilobyte of hashed memory, per thread\n"
        "    -r repetitions  -- A multiplier on the total number of times we hash\n"
        "    -t parallelism  -- Parallelism parameter, typically the number of threads\n"
        "    -b blockSize    -- Memory hashed in the inner loop at once, in bytes\n"
        "    -B subBlockSize -- Length of short reads from within a block in the inner loop\n");
    exit(1);
}

static uint32_t readuint32_t(char flag, char *arg) {
    char *endPtr;
    char *p = arg;
    uint32_t value = strtol(p, &endPtr, 0);
    if(*p == '\0' || *endPtr != '\0') {
        usage("Invalid integer for parameter -%c", flag);
    }
    return value;
}

// Read a 2-character hex byte.
static bool readHexByte(uint8_t *dest, char *value) {
    char c = toupper((uint8_t)*value++);
    uint8_t byte;
    if(c >= '0' && c <= '9') {
        byte = c - '0';
    } else if(c >= 'A' && c <= 'F') {
        byte = c - 'A' + 10;
    } else {
        return false;
    }
    byte <<= 4;
    c = toupper((uint8_t)*value);
    if(c >= '0' && c <= '9') {
        byte |= c - '0';
    } else if(c >= 'A' && c <= 'F') {
        byte |= c - 'A' + 10;
    } else {
        return false;
    }
    *dest = byte;
    return true;
}

static uint8_t *readHexSalt(char *p, uint32_t *saltLength) {
    uint32_t length = strlen(p);
    if(length & 1) {
        usage("hex salt string must have an even number of digits.\n");
    }
    *saltLength = strlen(p) >> 1;
    uint8_t *salt = malloc(*saltLength*sizeof(uint8_t));
    if(salt == NULL) {
        usage("Unable to allocate salt");
    }
    uint8_t *dest = salt;
    while(*p != '\0' && readHexByte(dest++, p)) {
        p += 2;
    }
    return salt;
}

int main(int argc, char **argv) {
    uint32_t memorySize = 2048*1024, derivedKeySize = 32;
    uint32_t repetitions = 1, parallelism = 2, blockSize = 16384, subBlockSize = 0;
    uint8_t garlic = 0;
    uint8_t *salt = (uint8_t *)"salt";
    uint32_t saltSize = 4;
    uint8_t *password = (uint8_t *)"password";
    uint32_t passwordSize = 8;
    uint32_t multipliesPerKB = 250;

    char c;
    while((c = getopt(argc, argv, "h:p:s:g:m:M:r:t:b:B:")) != -1) {
        switch (c) {
        case 'h':
            derivedKeySize = readuint32_t(c, optarg);
            break;
        case 'p':
            password = (uint8_t *)optarg;
            passwordSize = strlen(optarg);
            break;
        case 's':
            salt = readHexSalt(optarg, &saltSize);
            break;
        case 'g':
            garlic = readuint32_t(c, optarg);
            break;
        case 'm':
            memorySize = readuint32_t(c, optarg);
            break;
        case 'M':
            multipliesPerKB = readuint32_t(c, optarg);
            break;
        case 'r':
            repetitions = readuint32_t(c, optarg);
            break;
        case 't':
            parallelism = readuint32_t(c, optarg);
            break;
        case 'b':
            blockSize = readuint32_t(c, optarg);
            break;
        case 'B':
            subBlockSize = readuint32_t(c, optarg);
            break;
        default:
            usage("Invalid argumet");
        }
    }
    if(optind != argc) {
        usage("Extra parameters not recognised\n");
    }

    printf("garlic:%u memorySize:%u multipliesPerKB:%u repetitions:%u\n",
        garlic, memorySize, multipliesPerKB, repetitions);
    printf("numThreads:%u blockSize:%u subBlockSize:%u\n",
        parallelism, blockSize, subBlockSize);
    uint8_t *derivedKey = (uint8_t *)calloc(derivedKeySize, sizeof(uint8_t));
    if(!TigerKDF_HashPassword(derivedKey, derivedKeySize, password, passwordSize, salt, saltSize,
            memorySize, multipliesPerKB, garlic, NULL, 0, blockSize, subBlockSize, parallelism,
            repetitions, false)) {
        fprintf(stderr, "Key stretching failed.\n");
        return 1;
    }
    printHex("", derivedKey, derivedKeySize);
    return 0;
}
