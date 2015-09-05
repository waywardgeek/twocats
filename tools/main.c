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
#include <strings.h>
#include <getopt.h>
#include "twocats.h"

static void usage(char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, (char *)format, ap);
    va_end(ap);
    fprintf(stderr, "\nUsage: twocats [OPTIONS] [hashType]\n"
        "    -a algorithm     -- twocats, twocats-full, twocats-extended (default), or phs\n"
        "    -p password      -- Set the password to hash\n"
        "    -s salt          -- Set the salt.  Salt must be in hexidecimal\n"
        "    -m memCost       -- The amount of memory to use = 2^memCost KiB\n"
        "    -M multiplies    -- The number of multiplies per 32 bytes of hashing, from 0 to 8\n"
        "    -l lanes         -- The number of parallel data lanes to compute on a SIMD unit\n"
        "    -P parallelism   -- Parallelism parameter, typically the number of threads\n"
        "    -b blockSize     -- BlockSize, defaults to 16384\n"
        "    -B subBlockSize  -- SubBlockSize, defaults to 64\n"
        "    -o overwriteCost -- Overwrite memCost-overwriteCost memory (0 disables)\n"
        "    -i iterations    -- Call the hash function this number of times\n"
        "    -r               -- Enable side-channel-resistant mode\n"
        "Hash types are");
    
    for(uint32_t i = 0; i < TWOCATS_NONE; i++) {
        char *name = TwoCats_GetHashTypeName(i);
        printf(" %s", name);
    }
    printf("\n");
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
    uint8_t parallelism = TWOCATS_PARALLELISM;
    uint8_t memCost = TWOCATS_MEMCOST;
    uint8_t *password = malloc(8);
    uint32_t passwordSize = 8;
    memcpy(password, "password", 8);
    uint8_t *salt = malloc(4);
    uint32_t saltSize = 4;
    memcpy(salt, "salt", 4);
    uint8_t multiplies = TWOCATS_MULTIPLIES;
    uint32_t blockSize = TWOCATS_BLOCKSIZE;
    uint32_t subBlockSize = TWOCATS_SUBBLOCKSIZE;
    uint32_t lanes = TWOCATS_LANES;
    uint8_t overwriteCost = TWOCATS_OVERWRITECOST;
    TwoCats_HashType hashType = TWOCATS_BLAKE2S;
    char *hashName = "blake2s";
    char *algorithm = "twocats-extended";
    bool sideChannelResistant = false;
    uint32_t iterations = 1;

    char c;
    while((c = getopt(argc, argv, "a:i:p:rs:m:M:o:l:P:b:B:")) != -1) {
        switch (c) {
        case 'a':
            algorithm = optarg;
            break;
        case 'p':
            passwordSize = strlen(optarg);
            password = realloc(password, passwordSize);
            memcpy(password, optarg, passwordSize);
            break;
        case 's':
            free(salt);
            salt = readHexSalt(optarg, &saltSize);
            break;
        case 'm':
            memCost = readuint32_t(c, optarg);
            break;
        case 'M':
            multiplies = readuint32_t(c, optarg);
            break;
        case 'o':
            overwriteCost = readuint32_t(c, optarg);
            break;
        case 'l':
            lanes = readuint32_t(c, optarg);
            break;
        case 'P':
            parallelism = readuint32_t(c, optarg);
            break;
        case 'b':
            blockSize = readuint32_t(c, optarg);
            break;
        case 'B':
            subBlockSize = readuint32_t(c, optarg);
            break;
        case 'r':
            sideChannelResistant = true;
            break;
        case 'i':
            iterations = readuint32_t(c, optarg);
            break;
        default:
            usage("Invalid argument");
        }
    }
    if(optind + 1 == argc) {
        // Must have supplied a hash type
        hashName = argv[optind];
        hashType = TwoCats_FindHashType(argv[optind]);
        if(hashType == TWOCATS_NONE) {
            usage("Unsupported hash type: %s\n", hashName);
        }
    } else if(optind != argc) {
        usage("Too many arguments\n");
    }

    printf("hash:%s memCost:%u multiplies:%u lanes:%u parallelism:%u\n",
        hashName, memCost, multiplies, lanes, parallelism);
    printf("algorithm:%s password:%s salt:%s blockSize:%u subBlockSize:%u\n",
        algorithm, password, salt, blockSize, subBlockSize);
    uint8_t derivedKeySize = TwoCats_GetHashTypeSize(hashType);
    uint8_t derivedKey[derivedKeySize];
    for(uint32_t i = 0; i < iterations; i++) {
        if(!strcmp(algorithm, "twocats-extended")) {
            if(!TwoCats_HashPasswordExtended(NULL, hashType, derivedKey, password, passwordSize,
                    salt, saltSize, NULL, 0, memCost, memCost, multiplies, lanes, parallelism,
                    blockSize, subBlockSize, overwriteCost, false, sideChannelResistant)) {
                fprintf(stderr, "Key stretching failed.\n");
                return 1;
            }
        } else if(!strcmp(algorithm, "twocats-full")) {
            if(!TwoCats_HashPasswordFull(hashType, derivedKey, password, passwordSize,
                    salt, saltSize, memCost, parallelism, sideChannelResistant)) {
                fprintf(stderr, "Key stretching failed.\n");
                return 1;
            }
        } else if(!strcmp(algorithm, "twocats")) {
            if(!TwoCats_HashPassword(derivedKey, password, passwordSize, salt, saltSize, memCost)) {
                fprintf(stderr, "Key stretching failed.\n");
                return 1;
            }
        } else if(!strcmp(algorithm, "phs")) {
            if(PHS(derivedKey, derivedKeySize, password, passwordSize, salt, saltSize, memCost, parallelism)) {
                fprintf(stderr, "Key stretching failed.\n");
                return 1;
            }
        } else {
            usage("Invalid algorithm: %s\n", algorithm);
        }
    }
    TwoCats_PrintHex("", derivedKey, derivedKeySize);
    return 0;
}
