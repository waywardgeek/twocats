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
    puts(message);
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

// Prevents compiler optimizing out memset() -- from blake2-impl.h
static inline void secure_zero_memory(void *v, size_t n) {
    volatile uint8_t *p = ( volatile uint8_t * )v;
    while( n-- ) *p++ = 0;
}

// Verify that parameters are valid for password hashing.
static bool verifyParameters(uint32_t hashSize, uint32_t passwordSize, uint32_t saltSize, uint32_t memSize,
        uint32_t multiplies, uint8_t startGarlic, uint8_t stopGarlic, uint32_t dataSize, uint32_t blockSize,
        uint32_t subBlockSize, uint32_t parallelism, uint32_t repetitions) {
    if(subBlockSize == 0) {
        subBlockSize = blockSize;
    }
    if(hashSize > blockSize || hashSize < 12 || (hashSize & 0x3) || passwordSize > 1024 ||
            passwordSize == 0 || saltSize > 1024  || saltSize == 0 || memSize == 0 ||
            memSize > 1 << 30 || multiplies > 8 || startGarlic > stopGarlic || stopGarlic > 30 ||
            dataSize > 1024 || blockSize > 1 << 30 || blockSize & 0x1f || subBlockSize > blockSize ||
            subBlockSize & 0x1f || subBlockSize*(blockSize/subBlockSize) != blockSize ||
            ((uint64_t)memSize << 10) < 4*(uint64_t)blockSize*parallelism || parallelism == 0 ||
            parallelism > 1 << 20 || repetitions == 0 || repetitions > 1 << 30) {
        return false;
    }
    uint64_t totalSize = (uint64_t)memSize << (10 + stopGarlic);
    if(totalSize >> (10 + stopGarlic) != memSize || totalSize > 1LL << 50 || totalSize/blockSize > 1 << 30) {
        return false;
    }
    // numSubBlocks has to be a power of 2 so we can use a simple mask to select a random-ish one
    uint32_t numSubBlocks = blockSize/subBlockSize;
    while((numSubBlocks & 1) == 0) {
        numSubBlocks >>= 1;
    }
    if(numSubBlocks != 1) {
        return false;
    }
    return true;
}

// A simple password hashing interface.  MemSize is in KiB.  The password is cleared with secure_zero_memory.
bool TigerKDF_SimpleHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
        const uint8_t *salt, uint32_t saltSize, uint32_t memSize) {
    if(!verifyParameters(hashSize, passwordSize, saltSize, memSize, TIGERKDF_MULTIPLIES, 0, 0, 0,
            TIGERKDF_BLOCKSIZE, TIGERKDF_SUBBLOCKSIZE, 1, 1)) {
        return false;
    }
    PBKDF2(hash, hashSize, password, passwordSize, salt, saltSize);
    secure_zero_memory(password, passwordSize);
    return TigerKDF(hash, hashSize, memSize, 200, 0, 0, 16384, 32, 2, 1, false);
}

// The full password hashing interface.  MemSize is in KiB.
bool TigerKDF_HashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint8_t passwordSize,
        const uint8_t *salt, uint32_t saltSize, uint32_t memSize, uint32_t multiplies, uint8_t garlic,
        uint8_t *data, uint32_t dataSize, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism,
        uint32_t repetitions, bool clearPassword) {
    if(!verifyParameters(hashSize, passwordSize, saltSize, memSize, multiplies, 0, garlic, dataSize,
            blockSize, subBlockSize, parallelism, repetitions)) {
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
        secure_zero_memory(password, passwordSize);
        if(data != NULL && dataSize != 0) {
            secure_zero_memory(data, dataSize);
        }
    }
    return TigerKDF(hash, hashSize, memSize, multiplies, 0, garlic, blockSize, subBlockSize, parallelism,
        repetitions, false);
}

// Update an existing password hash to a more difficult level of garlic.
bool TigerKDF_UpdatePasswordHash(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multiplies,
        uint8_t oldGarlic, uint8_t newGarlic, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism,
        uint32_t repetitions) {
    if(!verifyParameters(hashSize, 16, 16, memSize, multiplies, oldGarlic, newGarlic, 0,
            blockSize, subBlockSize, parallelism, repetitions)) {
        return false;
    }
    return TigerKDF(hash, hashSize, memSize, multiplies, oldGarlic, newGarlic,
        blockSize, subBlockSize, parallelism, repetitions, false);
}

// Client-side portion of work for server-relief mode.
bool TigerKDF_ClientHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint8_t passwordSize,
        const uint8_t *salt, uint32_t saltSize, uint32_t memSize, uint32_t multiplies, uint8_t garlic,
        uint8_t *data, uint32_t dataSize, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism,
        uint32_t repetitions, bool clearPassword) {
    if(!verifyParameters(hashSize, passwordSize, saltSize, memSize, multiplies, 0, garlic, dataSize,
            blockSize, subBlockSize, parallelism, repetitions)) {
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
        secure_zero_memory(password, passwordSize);
        if(data != NULL && dataSize != 0) {
            secure_zero_memory(data, dataSize);
        }
    }
    return TigerKDF(hash, hashSize, memSize, multiplies, 0, garlic, blockSize, subBlockSize,
        parallelism, repetitions, true);
}

// Server portion of work for server-relief mode.
void TigerKDF_ServerHashPassword(uint8_t *hash, uint32_t hashSize) {
    PBKDF2(hash, hashSize, hash, hashSize, NULL, 0);
}

// This is the prototype required for the password hashing competition.
// t_cost is a multiplier on CPU work.  m_cost is the number of KiB of memory to hash.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
        unsigned int t_cost, unsigned int m_cost) {
    return !TigerKDF_HashPassword(out, outlen, (void *)in, inlen, salt, saltlen, m_cost,
        TIGERKDF_MULTIPLIES, 0, NULL, 0, TIGERKDF_BLOCKSIZE, TIGERKDF_SUBBLOCKSIZE,
        TIGERKDF_PARALLELISM, t_cost, false);
}
