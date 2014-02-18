#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pbkdf2.h"
#include "tigerkdf.h"

bool TigerKDF(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multipliesPerBlock, uint8_t startGarlic,
        uint8_t stopGarlic, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism, uint32_t repetitions,
        bool skipLastHash);

// Verify that parameters are valid for password hashing.
static bool verifyParameters(uint32_t hashSize, uint32_t passwordSize, uint32_t saltSize, uint32_t memSize,
        uint32_t multipliesPerBlock, uint8_t startGarlic, uint8_t stopGarlic, uint32_t dataSize, uint32_t blockSize,
        uint32_t subBlockSize, uint32_t parallelism, uint32_t repetitions) {
    if(subBlockSize == 0) {
        subBlockSize = blockSize;
    }
    if(hashSize > 1024 || hashSize < 12 || (hashSize & 0x3) || passwordSize > 1024 ||
            passwordSize == 0 || saltSize > 1024  || saltSize == 0 || memSize == 0 ||
            memSize > 1 << 30 || multipliesPerBlock > blockSize || multipliesPerBlock == 0 ||
            (multipliesPerBlock & 0x7) != 0 || startGarlic > stopGarlic || stopGarlic > 30 ||
            dataSize > 1024 || blockSize > 1 << 30 || blockSize < hashSize ||
            blockSize & 0x1f || subBlockSize > blockSize || subBlockSize & 0x1f ||
            subBlockSize*(blockSize/subBlockSize) != blockSize ||
            ((uint64_t)memSize << 10) < 4*(uint64_t)blockSize*parallelism || parallelism == 0 ||
            parallelism > 1 << 20 || repetitions == 0 || repetitions > 1 << 30) {
        return false;
    }
    uint64_t totalSize = (uint64_t)memSize << (10 + stopGarlic);
    if(totalSize >> (10 + stopGarlic) != memSize || totalSize > 1LL << 50 || totalSize/blockSize > 1 << 30) {
        return false;
    }
    if(subBlockSize != blockSize) {
        while((subBlockSize & 1) == 0) {
            subBlockSize >>= 1;
        }
        if(subBlockSize != 1) {
            return false;
        }
    }
    return true;
}

// A simple password hashing interface.  MemSize is in KiB.  The password is cleared with memset.
bool TigerKDF_SimpleHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
        const uint8_t *salt, uint32_t saltSize, uint32_t memSize) {
    if(!verifyParameters(hashSize, passwordSize, saltSize, memSize, 4096, 0, 0, 0, 16384, 0, 1, 1)) {
        return false;
    }
    PBKDF2(hash, hashSize, password, passwordSize, salt, saltSize);
    memset(password, '\0', passwordSize);
    return TigerKDF(hash, hashSize, memSize, 3000, 0, 0, 16384, 0, 2, 1, false);
}

// The full password hashing interface.  MemSize is in KiB.
bool TigerKDF_HashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint8_t passwordSize,
        const uint8_t *salt, uint32_t saltSize, uint32_t memSize, uint32_t multipliesPerBlock, uint8_t garlic,
        uint8_t *data, uint32_t dataSize, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism,
        uint32_t repetitions, bool clearPassword) {
    if(!verifyParameters(hashSize, passwordSize, saltSize, memSize, multipliesPerBlock, 0, garlic, dataSize,
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
        memset(password, '\0', passwordSize);
        if(data != NULL && dataSize != 0) {
            memset(data, '\0', dataSize);
        }
    }
    return TigerKDF(hash, hashSize, memSize, multipliesPerBlock, 0, garlic, blockSize, subBlockSize, parallelism,
        repetitions, false);
}

// Update an existing password hash to a more difficult level of garlic.
bool TigerKDF_UpdatePasswordHash(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multipliesPerBlock,
        uint8_t oldGarlic, uint8_t newGarlic, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism,
        uint32_t repetitions) {
    if(!verifyParameters(hashSize, 16, 16, memSize, multipliesPerBlock, oldGarlic, newGarlic, 0,
            blockSize, subBlockSize, parallelism, repetitions)) {
        return false;
    }
    return TigerKDF(hash, hashSize, memSize, multipliesPerBlock, oldGarlic, newGarlic,
        blockSize, subBlockSize, parallelism, repetitions, false);
}

// Client-side portion of work for server-relief mode.
bool TigerKDF_ClientHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint8_t passwordSize,
        const uint8_t *salt, uint32_t saltSize, uint32_t memSize, uint32_t multipliesPerBlock, uint8_t garlic,
        uint8_t *data, uint32_t dataSize, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism,
        uint32_t repetitions, bool clearPassword) {
    if(!verifyParameters(hashSize, passwordSize, saltSize, memSize, multipliesPerBlock, 0, garlic, dataSize,
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
        memset(password, '\0', passwordSize);
        if(data != NULL && dataSize != 0) {
            memset(data, '\0', dataSize);
        }
    }
    return TigerKDF(hash, hashSize, memSize, multipliesPerBlock, 0, garlic, blockSize, subBlockSize ,
        parallelism, repetitions, true);
}

// Server portion of work for server-relief mode.
void TigerKDF_ServerHashPassword(uint8_t *hash, uint32_t hashSize) {
    H(hash, hashSize, hash, hashSize, NULL, 0);
}

// This is the prototype required for the password hashing competition.
// t_cost is an integer multiplier on CPU work.  m_cost is an integer number of KiB of memory to hash.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
        unsigned int t_cost, unsigned int m_cost) {
    return !TigerKDF_HashPassword(out, outlen, (void *)in, inlen, (void *)salt, saltlen, m_cost, 3000, 0,
        NULL, 0, 16384, 0, 2, t_cost, false);
}
