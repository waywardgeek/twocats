/*
   TigerKDF common functions between reference and optimized C versions.

   Written in 2014 by Bill Cox <waywardgeek@gmail.com>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "hkdf/sha.h"
#include "tigerkdf.h"
#include "tigerkdf-impl.h"

// Print the state.
void printState(char *message, uint32_t state[8]) {
    printf("%s\n", message);
    for(uint32_t i = 0; i < 8; i++) {
        printf("%u ", state[i]);
    }
    printf("\n");
}

// Print a value out in hex - from Catena.
void printHex(char *message, uint8_t *x, int len) {
    puts(message);
    for(uint32_t i = 0; i < len; i++) {
        if(i != 0 && i % 8 == 0) {
            puts("");
        }
        printf("%02x ", x[i]);
    }
    printf("     %d (octets)\n\n", len);
}

// Just dump memory in a format that can be passed to the dieharder tests with:
//   dieharder -a -g 202 -f dieharder_data
void dumpMemory(char *fileName, uint32_t *mem, uint64_t memlen) {
    FILE *file = fopen(fileName, "w");
    if(file == NULL) {
        fprintf(stderr, "Unable to open file %s for writing\n", fileName);
        return;
    }
    fprintf(file, "type: d\n");
    fprintf(file, "count: %lu\n", memlen);
    fprintf(file, "numbit: 32\n");
    for(uint64_t i = 0; i < memlen; i++) {
        fprintf(file, "%u\n", mem[i]);
    }
    fclose(file);
}

// This is used to determine block length and other parameters for each level of garlic (memCost)
void TigerKDF_ComputeSizes(uint8_t memCost, uint8_t timeCost, uint8_t *parallelism, uint32_t *blocklen,
    uint32_t *blocksPerThread, uint32_t *repetitions, uint8_t *multiplies) {

    // Expand time cost into multiplies and repetitions
    if(timeCost <= 8) {
        *multiplies = timeCost;
        *repetitions = 1;
    } else {
        *multiplies = 8;
        *repetitions = 1 << (timeCost - 8);
    }

    // We really want a decent number of blocks per thread, so if it's < TIGERKDF_MINBLOCKS, then reduce blocklen,
    // and if needed, parallelism
    uint64_t memlen = (1024/sizeof(uint32_t)) << memCost;
    *blocklen = TIGERKDF_BLOCKLEN;
    *blocksPerThread = TIGERKDF_SLICES*(memlen/(TIGERKDF_SLICES * *parallelism * *blocklen));
    if(*blocksPerThread < TIGERKDF_MINBLOCKS) {
        *blocksPerThread = TIGERKDF_MINBLOCKS;
        while(*parallelism * *blocksPerThread * *blocklen > memlen) {
            if(*blocklen > TIGERKDF_SUBBLOCKLEN) {
                *blocklen >>= 1;
            } else if(*parallelism > 1) {
                *parallelism = memlen/(*blocksPerThread * *blocklen);
                if(*parallelism == 0) {
                    *parallelism = 1;
                }
            } else {
                *blocksPerThread = memlen/(*parallelism * *blocklen);
            }
        }
    }
    //printf("For memCost %u -  parallelism:%u blocklen:%u blocksPerThread:%u repetitions:%u multiplies:%u\n",
        //memCost, *parallelism, *blocklen*4, *blocksPerThread, *repetitions, *multiplies);
}

// This is a simple wrapper around the official hkdfExtract function.
void TigerKDF_hkdfExtract(uint32_t hash256[8], uint8_t *hash, uint32_t hashSize) {
    uint8_t buf[32];
    if(hkdfExtract(SHA256, NULL, 0, hash, hashSize, buf)) {
        fprintf(stderr, "hkdfExtract failed\n");
        exit(1);
    }
    be32dec_vect(hash256, buf, 32);
    secureZeroMemory(buf, 32);
}

// This is a simple wrapper around the official hkdfExpand function.
void TigerKDF_hkdfExpand(uint8_t *hash, uint32_t hashSize, uint32_t hash256[8]) {
    uint8_t buf[32];
    be32enc_vect(buf, hash256, 32);
    if(hkdfExpand(SHA256, buf, 32, NULL, 0, hash, hashSize)) {
        fprintf(stderr, "hkdfExpand failed\n");
        exit(1);
    }
    secureZeroMemory(buf, 32);
}

// This is a simple wrapper around the official hkdf function, which hashes the hash onto itself.
void TigerKDF_hkdf(uint8_t *hash, uint32_t hashSize) {
    if(hkdf(SHA256, NULL, 0, hash, hashSize, (uint8_t *)"TigerKDF", 8, hash, hashSize)) {
        fprintf(stderr, "hkdf failed\n");
        exit(1);
    }
}

// Verify that parameters are valid for password hashing.
static bool verifyParameters(uint8_t hashSize, uint8_t startMemCost, uint8_t stopMemCost,
        uint8_t multiplies , uint8_t timeCost, uint8_t parallelism) {
    if(hashSize == 0 || hashSize > 255*32) {
        fprintf(stderr, "Invalid hash size: the range is 1 through 255*32\n");
        return false;
    }
    if(startMemCost > stopMemCost) {
        fprintf(stderr, "startMemCost must be <= stopMemCost\n");
        return false;
    }
    if(stopMemCost > 30) {
        fprintf(stderr, "stopMemCost must be <= 30\n");
        return false;
    }
    if(timeCost > 30) {
        fprintf(stderr, "timeCost must be <= 30\n");
        return false;
    }
    if(multiplies > 8) {
        fprintf(stderr, "timeCost must be <= 38\n");
        return false;
    }
    if(parallelism == 0) {
        fprintf(stderr, "parallelism must be from 1 to 255\n");
        return false;
    }
    return true;
}

// A simple password hashing interface.  The password is cleared with secureZeroMemory.
bool TigerKDF_SimpleHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
        const uint8_t *salt, uint32_t saltSize, uint8_t memCost, uint8_t timeCost) {
    uint8_t multiplies = 3; // Decent match for Intel Sandy Bridge through Haswell
    if(memCost <= 16*1024) {
        multiplies = 1; // Assume it fits in L1 cache
    } else if(memCost < 1024*1024) {
        multiplies = 2; // Assume it fits in L2 or L3 cache
    }
    return TigerKDF_HashPassword(hash, hashSize, password, passwordSize, salt, saltSize, NULL, 0, memCost,
        memCost, timeCost, multiplies, TIGERKDF_PARALLELISM, true, false);
}

// The full password hashing interface.  
bool TigerKDF_HashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
        const uint8_t *salt, uint32_t saltSize, uint8_t *data, uint32_t dataSize, uint8_t startMemCost,
        uint8_t stopMemCost, uint8_t timeCost, uint8_t multiplies, uint8_t parallelism,
        bool clearPassword, bool clearData) {
    if(!TigerKDF_ClientHashPassword(hash, hashSize, password, passwordSize, salt, saltSize, data, dataSize,
            startMemCost, stopMemCost, timeCost, multiplies, parallelism, clearPassword, clearData)) {
        return false;
    }
    TigerKDF_ServerHashPassword(hash, hashSize);
    return true;
}

// Update an existing password hash to a more difficult level of memory cost (garlic).
bool TigerKDF_UpdatePasswordMemCost(uint8_t *hash, uint32_t hashSize, uint8_t oldMemCost, uint8_t newMemCost,
        uint8_t timeCost, uint8_t multiplies, uint8_t parallelism) {
    if(!verifyParameters(hashSize, oldMemCost, newMemCost, timeCost, multiplies, parallelism)) {
        return false;
    }
    if(!TigerKDF(hash, hashSize, oldMemCost, newMemCost, timeCost, multiplies, parallelism, true)) {
        return false;
    }
    TigerKDF_ServerHashPassword(hash, hashSize);
    return true;
}

// Add a 32-bit value to the input.  Deal with conversion to big-endian.
static bool addUint32Input(HKDFContext *context, uint32_t value) {
    uint8_t buf[4];
    be32enc(buf, value);
    if(hkdfInput(context, buf, 4)) {
        fprintf(stderr, "Unable to add input to hkdf\n");
        return false;
    }
    return true;
}

// Add an byte to the input.
static bool addUint8Input(HKDFContext *context, uint8_t value) {
    if(hkdfInput(context, &value, 1)) {
        fprintf(stderr, "Unable to add input to hkdf\n");
        return false;
    }
    return true;
}

// Add an array of bytes to the input.
static bool addInput(HKDFContext *context, uint8_t *input, uint32_t inputSize) {
    if(hkdfInput(context, input, inputSize)) {
        fprintf(stderr, "Unable to add input to hkdf\n");
        return false;
    }
    return true;
}

// Client-side portion of work for server-relief mode.  Return true if there are no memory
// allocation errors.  The password and data are not cleared if there is an error.
bool TigerKDF_ClientHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
        const uint8_t *salt, uint32_t saltSize, uint8_t *data, uint32_t dataSize, uint8_t startMemCost,
        uint8_t stopMemCost, uint8_t timeCost, uint8_t multiplies, uint8_t parallelism,
        bool clearPassword, bool clearData) {
    if(!verifyParameters(hashSize, startMemCost, stopMemCost, timeCost, multiplies, parallelism)) {
        return false;
    }

    // Initialize the hkdf context with the salt
    HKDFContext context;
    memset(&context, 0, sizeof(HKDFContext));
    if(hkdfReset(&context, SHA256, salt, saltSize)) {
        fprintf(stderr, "Unable to initialize hkdf\n");
        return false;
    }

    // Add all the inputs, other than stopMemCost
    if(!addUint32Input(&context, hashSize) || !addUint32Input(&context, passwordSize) ||
            !addInput(&context, password, passwordSize) || !addUint32Input(&context, dataSize) ||
            !addInput(&context, data, dataSize) || !addUint8Input(&context, startMemCost) ||
            !addUint8Input(&context, timeCost) || !addUint8Input(&context, multiplies) ||
            !addUint8Input(&context, parallelism)) {
        fprintf(stderr, "Unable to add input to hkdf\n");
        return false;
    }
    // Now clear the password and data if allowed
    if(clearPassword && passwordSize != 0) {
        secureZeroMemory(password, passwordSize);
    }
    if(clearData && dataSize != 0) {
        secureZeroMemory(data, dataSize);
    }

    if(hkdfResult(&context, NULL, (uint8_t *)"TigerKDF", 8, hash, hashSize)) {
        fprintf(stderr, "Unable to finalize hkdf\n");
        return false;
    }
    return TigerKDF(hash, hashSize, startMemCost, stopMemCost, timeCost, multiplies, parallelism, false);
}

// Server portion of work for server-relief mode.
void TigerKDF_ServerHashPassword(uint8_t *hash, uint8_t hashSize) {
    TigerKDF_hkdf(hash, hashSize);
}

// This is the prototype required for the password hashing competition.
// t_cost is a multiplier on CPU work.  m_cost is garlic.
// If possible, call TigerKDF_SimpleHashPassword instead so that the password can be cleared.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
        unsigned int t_cost, unsigned int m_cost) {
    if(outlen >= 256 || inlen >= 256 || saltlen >= 256 || t_cost >= 256 || m_cost >= 256) {
        fprintf(stderr, "PHS: All input sizes must be < 256\n");
        return 1;
    }
    // Make a copy because SimpleHashPassword clears the password
    uint8_t buf[inlen];
    memcpy(buf, in, inlen);
    return !TigerKDF_SimpleHashPassword(out, outlen, buf, inlen, salt, saltlen, m_cost, t_cost);
}

// Just measure the time for a given memCost and timeCost.  Return -1 if memory allocation fails.
static clock_t findRuntime(uint8_t memCost, uint8_t timeCost) {
    uint8_t buf[TIGERKDF_KEYSIZE];
    clock_t start = clock();
    if(!TigerKDF_SimpleHashPassword(buf, TIGERKDF_KEYSIZE, NULL, 0, NULL, 0, memCost, timeCost)) {
        fprintf(stderr, "Memory hashing failed\n");
        return -1;
    }
    clock_t end = clock();
    return (end - start) * 1000 / CLOCKS_PER_SEC;
}

// Find a good timeCost for a given memCost on this machine.  This just finds the largest
// timeCost that doees not significantly slow down password hashing.  Returns 0 - 38 on
// success, or 255 on failure to allocate memory.
uint8_t TigerKDF_FindTimeCost(uint8_t memCost) {
    uint8_t timeCost = 0;
    clock_t minTime = findRuntime(memCost - 3, timeCost);
    while(true) {
        timeCost++;
        clock_t newTime = findRuntime(memCost - 3, timeCost);
        if(newTime == -1) {
            return 255;
        }
        if(newTime > minTime * 1.1) {
            return timeCost - 1;
        }
        if(timeCost == 8) {
            return timeCost;
        }
    }
}

// Find a good memCost for a given time on this machine.  This just finds the largest
// memCost that runs in less than milliSeconds ms.  Return 255 on failure to allocate memory.
uint8_t TigerKDF_FindMemCost(uint32_t milliSeconds, uint32_t maxMemCost) {
    uint8_t memCost = 1;
    while(true) {
        clock_t newTime = findRuntime(memCost, 0);
        if(newTime == -1) {
            return memCost - 1;
        }
        if(newTime > milliSeconds/8) {
            if(maxMemCost < memCost + 2) {
                return maxMemCost;
            }
            return memCost + 2;
        }
        if(memCost == maxMemCost) {
            return memCost;
        }
        memCost++;
    }
}
