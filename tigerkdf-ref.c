#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pbkdf2.h"
#include "tigerkdf.h"

// Forward declarations
static void hashWithoutPassword(uint32_t p, uint8_t *hash, uint32_t hashSize, uint32_t *mem,
        uint32_t blocklen, uint32_t numblocks, uint32_t repetitions);
static void hashWithPassword(uint32_t p, uint32_t *mem, uint32_t blocklen, uint32_t numblocks,
        uint32_t parallelism, uint32_t repetitions);
static inline uint32_t hashBlocks(uint32_t value, uint32_t *mem, uint32_t blocklen, uint64_t fromAddr,
        uint64_t toAddr, uint32_t repetitions);
static void xorIntoHash(uint8_t *hash, uint32_t hashSize, uint32_t *mem, uint32_t blocklen,
        uint32_t numblocks, uint32_t parallelism);
static uint32_t bitReverse(uint32_t value, uint32_t mask);

// The TigerKDF password hashing function.  MemSize is in MiB.
bool TigerKDF(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint8_t startGarlic, uint8_t stopGarlic,
        uint32_t blockSize, uint32_t parallelism, uint32_t repetitions, bool skipLastHash) {
    uint64_t memlen = (1 << 20)*(uint64_t)memSize/sizeof(uint32_t);
    uint32_t blocklen = blockSize/sizeof(uint32_t);
    uint32_t numblocks = (memlen/(2*parallelism*blocklen)) << startGarlic;
    memlen = (2*parallelism*(uint64_t)numblocks*blocklen) << (stopGarlic - startGarlic);
    uint32_t *mem = (uint32_t *)malloc(memlen*sizeof(uint32_t));
    if(mem == NULL) {
        return false;
    }
    uint8_t i;
    for(i = startGarlic; i <= stopGarlic; i++) {
        uint32_t p;
        for(p = 0; p < parallelism; p++) {
            hashWithoutPassword(p, hash, hashSize, mem, blocklen, numblocks, repetitions);
        }
        for(p = 0; p < parallelism; p++) {
            hashWithPassword(p, mem, blocklen, numblocks, parallelism, repetitions);
        }
        xorIntoHash(hash, hashSize, mem, blocklen, numblocks, parallelism);
        numblocks *= 2;
        if(i < stopGarlic || !skipLastHash) {
            H(hash, hashSize, hash, hashSize, NULL, 0);
        }
    }
    free(mem);
    return true;
}

// Hash memory without doing any password dependent memory addressing to thwart cache-timing-attacks.
static void hashWithoutPassword(uint32_t p, uint8_t *hash, uint32_t hashSize, uint32_t *mem,
        uint32_t blocklen, uint32_t numblocks, uint32_t repetitions) {
    uint64_t start = 2*p*(uint64_t)numblocks*blocklen;
    uint32_t keySize = blocklen*sizeof(uint32_t);
    uint8_t threadKey[keySize];
    uint8_t s[sizeof(uint32_t)];
    be32enc(s, p);
    H(threadKey, keySize, hash, hashSize, s, sizeof(uint32_t));
    be32dec_vect(mem + start, threadKey, blocklen*sizeof(uint32_t));
    uint32_t value = 1;
    uint32_t mask = 1;
    uint64_t toAddr = start + blocklen;
    uint32_t i;
    for(i = 1; i < numblocks; i++) {
        if(mask << 1 <= i) {
            mask = mask << 1;
        }
        uint32_t reversePos = bitReverse(i, mask);
        if(reversePos + mask < i) {
            reversePos += mask;
        }
        uint64_t fromAddr = start + (uint64_t)blocklen*reversePos;
        value = hashBlocks(value, mem, blocklen, fromAddr, toAddr, repetitions);
        toAddr += blocklen;
    }
}

// Hash memory with dependent memory addressing to thwart TMTO attacks.
static void hashWithPassword(uint32_t p, uint32_t *mem, uint32_t blocklen, uint32_t numblocks,
        uint32_t parallelism, uint32_t repetitions) {
    uint64_t start = (2*p + 1)*(uint64_t)numblocks*blocklen;
    uint32_t value = 1;
    uint64_t toAddr = start;
    uint32_t i;
    for(i = 0; i < numblocks; i++) {
        uint64_t v = value;
        uint64_t v2 = v*v >> 32;
        uint64_t v3 = v*v2 >> 32;
        uint32_t distance = (i + numblocks - 1)*v3 >> 32;
        uint64_t fromAddr;
        if(distance < i) {
            fromAddr = start + (i - 1 - distance)*(uint64_t)blocklen;
        } else {
            uint32_t q = (p + i) % parallelism;
            uint32_t b = numblocks - 1 - (distance - i);
            fromAddr = (2*numblocks*q + b)*(uint64_t)blocklen;
        }
        value = hashBlocks(value, mem, blocklen, fromAddr, toAddr, repetitions);
        toAddr += blocklen;
    }
}

// Hash three blocks together with a multiplication latency bound loop
static inline uint32_t hashBlocks(uint32_t value, uint32_t *mem, uint32_t blocklen, uint64_t fromAddr,
        uint64_t toAddr, uint32_t repetitions) {
    uint64_t prevAddr = toAddr - blocklen;
    uint32_t r;
    for(r = 0; r < repetitions; r++) {
        uint32_t i;
        for(i = 0; i < blocklen; i++) {
            value = value*(mem[prevAddr + i] | 3) + mem[fromAddr + i];
            mem[toAddr + i] = value;
        }
    }
    return value;
}

// XOR the last hashed data from each parallel process into the result.
static void xorIntoHash(uint8_t *hash, uint32_t hashSize, uint32_t *mem, uint32_t blocklen,
        uint32_t numblocks, uint32_t parallelism) {
    uint8_t data[hashSize];
    uint32_t p;
    for(p = 0; p < parallelism; p++) {
        uint64_t pos = 2*(p+1)*numblocks*(uint64_t)blocklen - hashSize/sizeof(uint32_t);
        be32enc_vect(data, mem + pos, hashSize);
        uint32_t i;
        for(i = 0; i < hashSize; i++) {
            hash[i] ^= data[i];
        }
    }
}

// Compute the bit reversal of value.
static uint32_t bitReverse(uint32_t value, uint32_t mask) {
    uint32_t result = 0;
    while(mask != 1) {
        result = (result << 1) | (value & 1);
        value >>= 1;
        mask >>= 1;
    }
    return result;
}
