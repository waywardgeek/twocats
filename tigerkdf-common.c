#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pbkdf2.h"
#include "tigerkdf.h"

bool TigerKDF(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multipliesPerBlock, uint8_t startGarlic,
        uint8_t stopGarlic, uint32_t blockSize, uint32_t parallelism, uint32_t repetitions, bool skipLastHash);

// Verify that parameters are valid for password hashing.
static bool verifyParameters(uint32_t hashSize, uint32_t passwordSize, uint32_t saltSize, uint32_t memSize,
        uint32_t multipliesPerBlock, uint8_t startGarlic, uint8_t stopGarlic, uint32_t dataSize, uint32_t blockSize,
        uint32_t parallelism, uint32_t repetitions) {
    if(hashSize > 1024 || hashSize < 12 || (hashSize & 0x3) || passwordSize > 1024 ||
            passwordSize == 0 || saltSize > 1024  || saltSize == 0 ||
            memSize == 0 || memSize > 1 << 30 || multipliesPerBlock > blockSize || startGarlic > stopGarlic ||
            stopGarlic > 30 || dataSize > 1024 || blockSize > 1 << 30 || blockSize < hashSize || blockSize & 0x3 ||
            ((uint64_t)memSize << 10) < 4*(uint64_t)blockSize*parallelism || parallelism == 0 ||
            parallelism > 1 << 20 || repetitions == 0 || repetitions > 1 << 30) {
        return false;
    }
    uint64_t totalSize = (uint64_t)memSize << (10 + stopGarlic);
    if(totalSize >> (10 + stopGarlic) != memSize || totalSize > 1LL << 50 || totalSize/blockSize > 1 << 30) {
        return false;
    }
    return true;
}

// This is the crytographically strong password hashing function based on PBKDF2.
void H(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize, uint8_t *salt,
        uint32_t saltSize) {
    uint8_t result[hashSize];
    PBKDF2_BLAKE2(password, passwordSize, salt, saltSize, 1, result, hashSize);
    memcpy(hash, result, hashSize);
}

// A simple password hashing interface.  MemSize is in MiB.
bool TigerKDF_SimpleHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
        uint8_t *salt, uint32_t saltSize, uint32_t memSize) {
    if(!verifyParameters(hashSize, passwordSize, saltSize, memSize, 4096, 0, 0, 0, 16384, 1, 1)) {
        return false;
    }
    H(hash, hashSize, password, passwordSize, salt, saltSize);
    return TigerKDF(hash, hashSize, memSize, 4096, 0, 0, 16384, 1, 1, false);
}

// The full password hashing interface.  MemSize is in MiB.
bool TigerKDF_HashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint8_t passwordSize,
        uint8_t *salt, uint32_t saltSize, uint32_t memSize, uint32_t multipliesPerBlock, uint8_t garlic,
        uint8_t *data, uint32_t dataSize, uint32_t blockSize, uint32_t parallelism, uint32_t repetitions) {
    if(!verifyParameters(hashSize, passwordSize, saltSize, memSize, multipliesPerBlock, 0, garlic, dataSize,
            blockSize, parallelism, repetitions)) {
        return false;
    }
    if(data != NULL && dataSize != 0) {
        uint8_t derivedSalt[hashSize];
        H(derivedSalt, hashSize, data, dataSize, salt, saltSize);
        H(hash, hashSize, password, passwordSize, derivedSalt, hashSize);
    } else {
        H(hash, hashSize, password, passwordSize, salt, saltSize);
    }
    return TigerKDF(hash, hashSize, memSize, multipliesPerBlock, 0, garlic, blockSize, parallelism, repetitions, false);
}

// Update an existing password hash to a more difficult level of garlic.
bool TigerKDF_UpdatePasswordHash(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multipliesPerBlock,
        uint8_t oldGarlic, uint8_t newGarlic, uint32_t blockSize, uint32_t parallelism, uint32_t repetitions) {
    if(!verifyParameters(hashSize, 16, 16, memSize, multipliesPerBlock, oldGarlic, newGarlic, 0,
            blockSize, parallelism, repetitions)) {
        return false;
    }
    return TigerKDF(hash, hashSize, memSize, multipliesPerBlock, oldGarlic, newGarlic, blockSize, parallelism,
            repetitions, false);
}

// Client-side portion of work for server-relief mode.
bool TigerKDF_ClientHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint8_t passwordSize,
        uint8_t *salt, uint32_t saltSize, uint32_t memSize, uint32_t multipliesPerBlock, uint8_t garlic,
        uint8_t *data, uint32_t dataSize, uint32_t blockSize, uint32_t parallelism, uint32_t repetitions) {
    if(!verifyParameters(hashSize, passwordSize, saltSize, memSize, multipliesPerBlock, 0, garlic, dataSize,
            blockSize, parallelism, repetitions)) {
        return false;
    }
    if(data != NULL && dataSize != 0) {
        uint8_t derivedSalt[hashSize];
        H(derivedSalt, hashSize, data, dataSize, salt, saltSize);
        H(hash, hashSize, password, passwordSize, derivedSalt, hashSize);
    } else {
        H(hash, hashSize, password, passwordSize, salt, saltSize);
    }
    return TigerKDF(hash, hashSize, memSize, multipliesPerBlock, 0, garlic, blockSize, parallelism, repetitions, true);
}

// Server portion of work for server-relief mode.
void TigerKDF_ServerHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t garlic) {
    H(hash, hashSize, hash, hashSize, &garlic, 1);
}

// This is the prototype required for the password hashing competition.
// t_cost is an integer multiplier on CPU work.  m_cost is an integer number of MiB of memory to hash.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
        unsigned int t_cost, unsigned int m_cost) {
    return !TigerKDF_HashPassword(out, outlen, (void *)in, inlen, (void *)salt, saltlen, m_cost, 4096, 0,
        NULL, 0, 16384, 2, t_cost);
}
