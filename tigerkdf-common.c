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
#include "pbkdf2.h"
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
    *blocksPerThread = memlen/(*parallelism * *blocklen);
    if(*blocksPerThread < TIGERKDF_MINBLOCKS) {
        *blocksPerThread = TIGERKDF_MINBLOCKS;
        while(*parallelism * *blocksPerThread * *blocklen > memlen) {
            if(*blocklen > TIGERKDF_SUBBLOCKLEN) {
                *blocklen = memlen/(*parallelism * *blocksPerThread);
                if(*blocklen < TIGERKDF_SUBBLOCKLEN) {
                    *blocklen = TIGERKDF_SUBBLOCKLEN;
                }
            } else if(*parallelism > 1) {
                *parallelism = memlen/(*blocksPerThread * *blocklen);
                if(*parallelism == 1) {
                    *parallelism = 1;
                }
            } else {
                *blocksPerThread = memlen/(*parallelism * *blocklen);
            }
        }
    }
    printf("For memCost %u -  parallelism:%u blocklen:%u blocksPerThread:%u repetitions:%u multiplies:%u\n",
        memCost, *parallelism, *blocklen*4, *blocksPerThread, *repetitions, *multiplies);
}

// Verify that parameters are valid for password hashing.
static bool verifyParameters(uint8_t hashSize, uint8_t startMemCost, uint8_t stopMemCost, uint8_t timeCost,
        uint8_t parallelism) {
    if(hashSize == 0 || (hashSize & 0x3)) {
        fprintf(stderr, "Invalid hash size: the range is 4 through 252 in multiples of 4\n");
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
    if(timeCost > 38) {
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
bool TigerKDF_SimpleHashPassword(uint8_t *hash, uint8_t hashSize, uint8_t *password, uint8_t passwordSize,
        const uint8_t *salt, uint8_t saltSize, uint8_t memCost, uint8_t timeCost) {
    return TigerKDF_HashPassword(hash, hashSize, password, passwordSize, salt, saltSize, NULL, 0, memCost,
        memCost, timeCost, TIGERKDF_PARALLELISM, true);
}

// The full password hashing interface.  
bool TigerKDF_HashPassword(uint8_t *hash, uint8_t hashSize, uint8_t *password, uint8_t passwordSize,
        const uint8_t *salt, uint8_t saltSize, uint8_t *data, uint8_t dataSize, uint8_t startMemCost,
        uint8_t stopMemCost, uint8_t timeCost, uint8_t parallelism, bool clearPassword) {
    if(!TigerKDF_ClientHashPassword(hash, hashSize, password, passwordSize, salt, saltSize, data, dataSize,
            startMemCost, stopMemCost, timeCost, parallelism, clearPassword)) {
        return false;
    }
    TigerKDF_ServerHashPassword(hash, hashSize);
    return true;
}

// Update an existing password hash to a more difficult level of memory cost (garlic).
bool TigerKDF_UpdatePasswordMemCost(uint8_t *hash, uint8_t hashSize, uint8_t oldMemCost, uint8_t newMemCost,
        uint8_t timeCost, uint8_t parallelism) {
    if(!verifyParameters(hashSize, oldMemCost, newMemCost, timeCost, parallelism)) {
        return false;
    }
    if(!TigerKDF(hash, hashSize, oldMemCost, newMemCost, timeCost, parallelism, true)) {
        return false;
    }
    TigerKDF_ServerHashPassword(hash, hashSize);
    return true;
}

// Client-side portion of work for server-relief mode.
bool TigerKDF_ClientHashPassword(uint8_t *hash, uint8_t hashSize, uint8_t *password, uint8_t passwordSize,
        const uint8_t *salt, uint8_t saltSize, uint8_t *data, uint8_t dataSize, uint8_t startMemCost,
        uint8_t stopMemCost, uint8_t timeCost, uint8_t parallelism, bool clearPassword) {
    if(!verifyParameters(hashSize, startMemCost, stopMemCost, timeCost, parallelism)) {
        return false;
    }
    if(data != NULL && dataSize != 0) {
        uint8_t derivedSalt[hashSize];
        PBKDF2(derivedSalt, hashSize, data, dataSize, salt, saltSize);
        PBKDF2(hash, hashSize, password, passwordSize, derivedSalt, hashSize);
    } else {
        PBKDF2(hash, hashSize, password, passwordSize, salt, saltSize);
    }
    if(clearPassword) {
        secureZeroMemory(password, passwordSize);
        secureZeroMemory(data, dataSize);
    }
    return TigerKDF(hash, hashSize, startMemCost, stopMemCost, timeCost, parallelism, false);
}

// Server portion of work for server-relief mode.
void TigerKDF_ServerHashPassword(uint8_t *hash, uint8_t hashSize) {
    PBKDF2(hash, hashSize, hash, hashSize, NULL, 0);
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
