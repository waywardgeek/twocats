/*
   TigerKDF reference C implementation

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
#include "tigerkdf.h"
#include "tigerkdf-impl.h"

// Add the last hashed data from each memory thread into the result.
static void combineHashes(uint8_t *hash, uint32_t hashSize, uint32_t *mem, uint32_t blocklen, uint32_t numblocks,
        uint32_t parallelism) {
    uint32_t hashlen = hashSize/4;
    uint32_t s[hashlen];
    memset(s, '\0', hashSize);
    for(uint32_t p = 0; p < parallelism; p++) {
        uint64_t pos = 2*(p+1)*numblocks*(uint64_t)blocklen - hashlen;
        for(uint32_t i = 0; i < hashlen; i++) {
            s[i] ^= mem[pos + i];
        }
    }
    uint8_t buf[hashSize];
    be32enc_vect(buf, s, hashSize);
    for(uint32_t i = 0; i < hashSize; i++) {
        hash[i] ^= buf[i];
    }
}

// Compute the bit reversal of v.
static uint32_t reverse(uint32_t v, uint32_t numBits) {
    uint32_t result = 0;
    while(numBits-- != 0) {
        result = (result << 1) | (v & 1);
        v >>= 1;
    }
    return result;
}

// Hash three blocks together with fast SSE friendly hash function optimized for high memory bandwidth.
static inline void hashBlocks(uint32_t state[8], uint32_t *mem, uint32_t blocklen, uint32_t subBlocklen,
        uint64_t fromAddr, uint64_t toAddr, uint32_t multiplies, uint32_t repetitions) {
    uint64_t prevAddr = toAddr - blocklen;
    uint32_t numSubBlocks = blocklen/subBlocklen;
    uint32_t mask = numSubBlocks - 1;
    uint32_t origState[8];
    memcpy(origState, state, 32);
    uint32_t v = 1;
    for(uint32_t r = 0; r < repetitions; r++) {
        uint32_t *f = mem + fromAddr;
        uint32_t *t = mem + toAddr;
        for(uint32_t i = 0; i < numSubBlocks; i++) {
            uint32_t randVal = *f;
            uint32_t *p = mem + prevAddr + subBlocklen*(randVal & mask);
            for(uint32_t j = 0; j < subBlocklen/8; j++) {
                for(uint32_t k = 0; k < multiplies; k++) {
                    v *= randVal | 1;
                    v ^= origState[k];
                }
                for(uint32_t k = 0; k < 8; k++) {
                    state[k] = (state[k] + *p++) ^ *f++;
                    state[k] = (state[k] >> 24) | (state[k] << 8);
                    *t++ = state[k];
                }
            }
        }
    }
    state[0] += v;
}

// Hash memory without doing any password dependent memory addressing to thwart cache-timing-attacks.
// Use Solar Designer's sliding-power-of-two window, with Catena's bit-reversal.
static void hashWithoutPassword(uint32_t *mem, uint32_t hash[32], uint32_t p,
        uint32_t blocklen, uint32_t numblocks, uint32_t multiplies, uint32_t repetitions) {
    uint64_t start = 2*p*(uint64_t)numblocks*blocklen;
    memset(mem + start, 0x5c, blocklen*sizeof(uint32_t));
    uint32_t state[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    hashWithSalt(mem + start, hash, p);
    uint32_t numBits = 0;
    uint64_t toAddr = start + blocklen;
    for(uint32_t i = 1; i < numblocks; i++) {
        if(1 << (numBits + 1) <= i) {
            numBits++;
        }
        uint32_t reversePos = reverse(i, numBits);
        if(reversePos + (1 << numBits) < i) {
            reversePos += 1 << numBits;
        }
        uint64_t fromAddr = start + (uint64_t)blocklen*reversePos;
        hashBlocks(state, mem, blocklen, blocklen, fromAddr, toAddr, multiplies, repetitions);
        hashWithSalt(state, state, i);
        toAddr += blocklen;
    }
}

// Hash memory with dependent memory addressing to thwart TMTO attacks.
static void hashWithPassword(uint32_t *mem, uint32_t parallelism, uint32_t p, uint32_t blocklen,
        uint32_t subBlocklen, uint32_t numblocks, uint32_t multiplies, uint32_t repetitions) {
    uint64_t start = (2*p + 1)*(uint64_t)numblocks*blocklen;
    uint32_t state[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    uint64_t toAddr = start;
    for(uint32_t i = 0; i < numblocks; i++) {
        uint64_t v = state[0];
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
        hashBlocks(state, mem, blocklen, subBlocklen, fromAddr, toAddr, multiplies, repetitions);
        hashWithSalt(state, state, i);
        toAddr += blocklen;
    }
}

// Compute the TigerKDF hash.
static void hashMemory(uint8_t *hash, uint32_t hashSize, uint32_t *mem, uint32_t numblocks, uint32_t blocklen,
        uint32_t subBlocklen, uint32_t multiplies, uint32_t parallelism, uint32_t repetitions) {

    // Convert hash to 8 32-bit ints.
    uint32_t hash256[8];
    hashTo256(hash256, hash, hashSize);

    // Do the the first "pure" loop
    for(uint32_t p = 0; p < parallelism; p++) {
        hashWithoutPassword(mem, hash256, p, blocklen, numblocks, multiplies, repetitions);
    }

    // Do the second "dirty" loop
    for(uint32_t p = 0; p < parallelism; p++) {
        hashWithPassword(mem, parallelism, p, blocklen, subBlocklen, numblocks, multiplies, repetitions);
    }

    // Combine all the memory thread hashes with a crypto-strength hash.
    combineHashes(hash, hashSize, mem, blocklen, numblocks, parallelism);
    PBKDF2(hash, hashSize, hash, hashSize, NULL, 0);
}

// The TigerKDF password hashing function.  MemSize is in KiB.
bool TigerKDF(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multiplies, uint8_t startGarlic,
        uint8_t stopGarlic, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism, uint32_t repetitions,
        bool serverReliefMode) {

    // Compute sizes
    uint64_t memlen = (1 << 10)*(uint64_t)memSize/sizeof(uint32_t);
    uint32_t blocklen = blockSize/sizeof(uint32_t);
    uint32_t numblocks = (memlen/(2*parallelism*blocklen)) << startGarlic;
    uint32_t subBlocklen = subBlockSize != 0? subBlockSize/sizeof(uint32_t) : blocklen;
    memlen = (2*parallelism*(uint64_t)numblocks*blocklen) << (stopGarlic - startGarlic);

    // Allocate memory
    uint32_t *mem = malloc(memlen*sizeof(uint32_t));
    if(mem == NULL) {
        return false;
    }

    // Iterate through the levels of garlic
    for(uint8_t i = startGarlic; i <= stopGarlic; i++) {
        hashMemory(hash, hashSize, mem, numblocks, blocklen, subBlocklen, multiplies, parallelism, repetitions);
        if(i < stopGarlic || !serverReliefMode) {
            // For server relief mode, skip doing this last hash
            PBKDF2(hash, hashSize, hash, hashSize, NULL, 0);
        }
        // Double the memory for the next round of garlic
        numblocks *= 2;
    }

    // The light is green, the trap is clean
    free(mem);
    return true;
}
