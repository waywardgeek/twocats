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

// Do low memory-bandwidth multiplication hashing.
static void multHash(uint32_t hash[8], uint32_t numblocks, uint32_t repetitions,
        uint32_t *multHashes, uint32_t multipliesPerBlock, uint32_t parallelism) {
    uint32_t state[8];
    hashWithSalt(state, hash, parallelism);
    for(uint32_t i = 0; i < numblocks*2; i++) {
        for(uint32_t j = 0; j < multipliesPerBlock * repetitions; j++) {
            // This is reversible, and will not lose entropy
            state[j&7] = (state[j&7]*(state[(j+1)&7] | 1)) ^ (state[(j+2)&7] >> 1);
        }
        // Apply a crypto-strength hash to the state and broadcast the result
        hashWithSalt(state, state, i);
        memcpy(multHashes + 8*i, state, 32);
    }
}

// Add the last hashed data from each memory thread into the result.
static void combineHashes(uint8_t *hash, uint32_t hashSize, uint32_t *mem, uint32_t blocklen, uint32_t numblocks,
        uint32_t parallelism) {
    uint32_t hashlen = hashSize/4;
    uint32_t s[hashlen];
    memset(s, '\0', hashSize);
    for(uint32_t p = 0; p < parallelism; p++) {
        uint64_t pos = 2*(p+1)*numblocks*(uint64_t)blocklen - hashlen;
        for(uint32_t i = 0; i < hashlen; i++) {
            s[i] += mem[pos + i];
        }
    }
    be32enc_vect(hash, s, hashSize);
}

// Hash the multiply chain state into our state.  If the multiplies are falling behind, sleep for a while.
static void hashMultIntoState(uint32_t iteration, uint32_t *multHashes, uint32_t *state) {
    for(uint32_t i = 0; i < 8; i++) {
        state[i] += multHashes[iteration*8 + i];
    }
    hashWithSalt(state, state, iteration);
}

// Compute the bit reversal of value.
static uint32_t reverse(uint32_t value, uint32_t numBits) {
    uint32_t result = 0;
    while(numBits-- != 0) {
        result = (result << 1) | (value & 1);
        value >>= 1;
    }
    return result;
}

// Hash three blocks together with fast SSE friendly hash function optimized for high memory bandwidth.
static inline void hashBlocks(uint32_t state[8], uint32_t *mem, uint32_t blocklen, uint32_t subBlocklen,
        uint64_t fromAddr, uint64_t toAddr, uint32_t repetitions) {
    uint64_t prevAddr = toAddr - blocklen;
    uint32_t numSubBlocks = blocklen/subBlocklen;
    uint32_t mask = numSubBlocks - 1;
    for(uint32_t r = 0; r < repetitions; r++) {
        uint32_t *f = mem + fromAddr;
        uint32_t *t = mem + toAddr;
        for(uint32_t i = 0; i < numSubBlocks; i++) {
            uint32_t *p = mem + prevAddr + subBlocklen*(*f & mask);
            for(uint32_t j = 0; j < subBlocklen/8; j++) {
                for(uint32_t k = 0; k < 8; k++) {
                    state[k] = (state[k] + *p++) ^ *f++;
                    state[k] = (state[k] >> 24) | (state[k] << 8);
                    *t++ = state[k];
                }
            }
        }
    }
}

// Hash memory without doing any password dependent memory addressing to thwart cache-timing-attacks.
// Use Solar Designer's sliding-power-of-two window, with Catena's bit-reversal.
static void hashWithoutPassword(uint32_t *mem, uint32_t hash[32], uint32_t p,
        uint32_t blocklen, uint32_t numblocks, uint32_t repetitions, uint32_t *multHashes) {
    uint64_t start = 2*p*(uint64_t)numblocks*blocklen;
    memset(mem + start, 0x5c, blocklen*sizeof(uint32_t));
    uint32_t state[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    hashWithSalt(mem + start, hash, p);
    hashMultIntoState(0, multHashes, state);
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
        hashBlocks(state, mem, blocklen, blocklen, fromAddr, toAddr, repetitions);
        hashMultIntoState(i, multHashes, state);
        toAddr += blocklen;
    }
}

// Hash memory with dependent memory addressing to thwart TMTO attacks.
static void hashWithPassword(uint32_t *mem, uint32_t parallelism, uint32_t p, uint32_t blocklen,
        uint32_t subBlocklen, uint32_t numblocks, uint32_t repetitions, uint32_t *multHashes) {
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
        hashBlocks(state, mem, blocklen, subBlocklen, fromAddr, toAddr, repetitions);
        hashMultIntoState(i + numblocks, multHashes, state);
        toAddr += blocklen;
    }
}

// The TigerKDF password hashing function.  MemSize is in KiB.
bool TigerKDF(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multipliesPerKB, uint8_t startGarlic,
        uint8_t stopGarlic, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism, uint32_t repetitions,
        bool skipLastHash) {
    // Compute sizes
    uint64_t memlen = (1 << 10)*(uint64_t)memSize/sizeof(uint32_t);
    uint32_t blocklen = blockSize/sizeof(uint32_t);
    uint32_t numblocks = (memlen/(2*parallelism*blocklen)) << startGarlic;
    uint32_t subBlocklen = subBlockSize != 0? subBlockSize/sizeof(uint32_t) : blocklen;
    memlen = (2*parallelism*(uint64_t)numblocks*blocklen) << (stopGarlic - startGarlic);
    uint32_t multipliesPerBlock = 8*(multipliesPerKB*(uint64_t)blockSize/(8*1024));
    if(multipliesPerBlock == 0) {
        multipliesPerBlock = 8;
    }
    // Allocate memory
    uint32_t *mem = malloc(memlen*sizeof(uint32_t));
    if(mem == NULL) {
        return false;
    }
    uint32_t *multHashes = malloc(8*sizeof(uint32_t)*memlen/blocklen);
    if(multHashes == NULL) {
        return false;
    }
    // Iterate through the levels of garlic
    for(uint8_t i = startGarlic; i <= stopGarlic; i++) {
        // Convert hash to 8 32-bit ints.
        uint32_t hash256[8];
        hashTo256(hash256, hash, hashSize);
        // Do the multiplication chains
        multHash(hash256, numblocks, repetitions, multHashes, multipliesPerBlock, parallelism);
        // Do the the first "pure" loop
        uint32_t p;
        for(p = 0; p < parallelism; p++) {
            hashWithoutPassword(mem, hash256, p, blocklen, numblocks, repetitions, multHashes);
        }
        // Do the second "dirty" loop
        for(p = 0; p < parallelism; p++) {
            hashWithPassword(mem, parallelism, p, blocklen, subBlocklen, numblocks, repetitions, multHashes);
        }
        // Combine all the memory thread hashes with a crypto-strength hash
        combineHashes(hash, hashSize, mem, blocklen, numblocks, parallelism);
        // Double the memory for the next round of garlic
        numblocks *= 2;
        if(i < stopGarlic || !skipLastHash) {
            // For server relief mode, skip doing this last hash
            PBKDF2(hash, hashSize, hash, hashSize, NULL, 0);
        }
    }
    // The light is green, the trap is clean
    free(multHashes);
    free(mem);
    return true;
}
