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

// Verify that parameters are valid for password hashing.  Adjust block and subBlock size
// rather than failing.
static bool verifyParameters(uint32_t hashSize, uint32_t passwordSize, uint32_t saltSize,  uint32_t dataSize,
        uint8_t startMemCost, uint8_t stopMemCost, uint8_t timeCost, uint32_t blockSize, uint32_t subBlockSize,
        uint32_t parallelism) {
    if(hashSize > 1024 || hashSize < 4 || (hashSize & 0x3) || passwordSize > 1024 ||
            passwordSize == 0 || saltSize > 1024 || saltSize == 0 || dataSize > 1024 || startMemCost > stopMemCost ||
            stopMemCost > 30 || blockSize > 1 << 30 || blockSize & 0x1f ||
            subBlockSize > blockSize || subBlockSize & 0x1f || subBlockSize*(blockSize/subBlockSize) !=  blockSize ||
            parallelism == 0 || parallelism > 1024 || timeCost > 38) {
        return false;
    }
    // numSubBlocks has to be a power of 2 so we can use a simple mask to select a random-ish one
    uint32_t numSubBlocks =  blockSize/subBlockSize;
    while((numSubBlocks & 1) == 0) {
        numSubBlocks >>= 1;
    }
    if(numSubBlocks != 1) {
        return false;
    }
    return true;
}

// A simple password hashing interface.  The password is cleared with secureZeroMemory.
bool TigerKDF_SimpleHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
        const uint8_t *salt, uint32_t saltSize, uint8_t memCost, uint8_t timeCost) {
    return TigerKDF_HashPassword(hash, hashSize, password, passwordSize, salt, saltSize, NULL, 0, memCost,
        memCost, timeCost, TIGERKDF_BLOCKSIZE, TIGERKDF_SUBBLOCKSIZE, TIGERKDF_PARALLELISM, true);
}

// The full password hashing interface.  
bool TigerKDF_HashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
        const uint8_t *salt, uint32_t saltSize, uint8_t *data, uint32_t dataSize,
        uint8_t startMemCost, uint8_t stopMemCost, uint8_t timeCost,
        uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism, bool clearPassword) {
    if(!TigerKDF_ClientHashPassword(hash, hashSize, password, passwordSize, salt, saltSize, data, dataSize,
            startMemCost, stopMemCost, timeCost, blockSize, subBlockSize, parallelism, clearPassword)) {
        return false;
    }
    TigerKDF_ServerHashPassword(hash, hashSize);
    return true;
}

// Update an existing password hash to a more difficult level of memory cost (garlic).
bool TigerKDF_UpdatePasswordMemCost(uint8_t *hash, uint32_t hashSize,
        uint8_t oldMemCost, uint8_t newMemCost, uint8_t timeCost,
        uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism) {
    if(!verifyParameters(hashSize, 16, 16, 0, oldMemCost, newMemCost, timeCost, blockSize, subBlockSize,
            parallelism)) {
        return false;
    }
    if(!TigerKDF(hash, hashSize, oldMemCost, newMemCost, timeCost, blockSize/sizeof(uint32_t),
            subBlockSize/sizeof(uint32_t), parallelism, true)) {
        return false;
    }
    TigerKDF_ServerHashPassword(hash, hashSize);
    return true;
}

// Client-side portion of work for server-relief mode.
bool TigerKDF_ClientHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint8_t passwordSize,
        const uint8_t *salt, uint32_t saltSize, uint8_t *data, uint32_t dataSize,
        uint8_t startMemCost, uint8_t stopMemCost, uint8_t timeCost,
        uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism, bool clearPassword) {
    if(!verifyParameters(hashSize, passwordSize, saltSize, dataSize, startMemCost, stopMemCost, timeCost,
            blockSize, subBlockSize, parallelism)) {
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
        if(data != NULL && dataSize != 0) {
            secureZeroMemory(data, dataSize);
        }
    }
    return TigerKDF(hash, hashSize, startMemCost, stopMemCost, timeCost, blockSize/sizeof(uint32_t),
            subBlockSize/sizeof(uint32_t), parallelism, false);
}

// Server portion of work for server-relief mode.
void TigerKDF_ServerHashPassword(uint8_t *hash, uint32_t hashSize) {
    PBKDF2(hash, hashSize, hash, hashSize, NULL, 0);
}

// This is the prototype required for the password hashing competition.
// t_cost is a multiplier on CPU work.  m_cost is garlic.
// If possible, call TigerKDF_SimpleHashPassword instead so that the password can be cleared.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
        unsigned int t_cost, unsigned int m_cost) {
    // Make a copy because SimpleHashPassword clears the password
    uint8_t buf[inlen];
    memcpy(buf, in, inlen);
    return !TigerKDF_SimpleHashPassword(out, outlen, buf, inlen, salt, saltlen, m_cost, t_cost);
}
