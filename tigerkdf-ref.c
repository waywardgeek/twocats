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

// Add the last hashed data into the result.
static void addIntoHash(uint32_t *hash256, uint32_t *mem, uint32_t parallelism, uint32_t blocklen,
        uint32_t blocksPerThread) {
    for(uint32_t p = 0; p < parallelism; p++) {
        for(uint32_t i = 0; i < 8; i++) {
            hash256[i] += mem[(p+1)*(uint64_t)blocklen*blocksPerThread + i - 8];
        }
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
        uint64_t fromAddr, uint64_t prevAddr, uint64_t toAddr, uint32_t multiplies, uint32_t repetitions) {

    // Do SIMD friendly memory hashing and a scalar CPU friendly parallel multiplication chain
    uint32_t numSubBlocks = blocklen/subBlocklen;
    uint32_t oddState[8];
    for(uint32_t i = 0; i < 8; i++) {
        oddState[i] = state[i] | 1;
    }
    int64_t v = 1;

    for(uint32_t r = 0; r < repetitions; r++) {
        uint32_t *f = mem + fromAddr;
        uint32_t *t = mem + toAddr;
        for(uint32_t i = 0; i < numSubBlocks; i++) {
            uint32_t randVal = *f;
            uint32_t *p = mem + prevAddr + subBlocklen*(randVal & (numSubBlocks - 1));
            for(uint32_t j = 0; j < subBlocklen/8; j++) {

                // Compute the multiplication chain
                for(uint32_t k = 0; k < multiplies; k++) {
                    v = (int32_t)v * (int64_t)oddState[k];
                    v ^= randVal;
                    randVal += v >> 32;
                }

                // Hash 32 bytes of memory
                for(uint32_t k = 0; k < 8; k++) {
                    state[k] = (state[k] + *p++) ^ *f++;
                    state[k] = (state[k] >> 24) | (state[k] << 8);
                    *t++ = state[k];
                }
            }
        }
    }
    hashWithSalt(state, state, v);
}

// Hash memory without doing any password dependent memory addressing to thwart cache-timing-attacks.
// Use Solar Designer's sliding-power-of-two window, with Catena's bit-reversal.
static void hashWithoutPassword(uint32_t *state, uint32_t *mem, uint32_t p, uint64_t blocklen,
        uint32_t blocksPerThread, uint32_t multiplies, uint32_t repetitions, uint32_t parallelism,
        uint32_t completedBlocks) {

    uint64_t start = blocklen*blocksPerThread*p;
    uint32_t firstBlock = completedBlocks;
    if(completedBlocks == 0) {
        // Initialize the first block of memory
        for(uint32_t i = 0; i < blocklen/8; i++) {
            hashWithSalt(mem + start + 8*i, state, i);
        }
        firstBlock = 1;
    }

    // Hash one "slice" worth of memory hashing
    uint32_t numBits = 1; // The number of bits in i
    for(uint32_t i = firstBlock; i < completedBlocks + blocksPerThread/TIGERKDF_SLICES; i++) {
        while(1 << numBits <= i) {
            numBits++;
        }

        // Compute the "sliding reverse" block position
        uint32_t reversePos = reverse(i, numBits-1);
        if(reversePos + (1 << (numBits-1)) < i) {
            reversePos += 1 << (numBits-1);
        }
        uint64_t fromAddr = blocklen*reversePos; // Start for fromAddr is computed in hashBlocks

        // Compute which thread's memory to read from
        if(fromAddr < completedBlocks*blocklen) {
            fromAddr += blocklen*blocksPerThread*(i % parallelism);
        } else {
            fromAddr += start;
        }

        uint64_t toAddr = start + i*blocklen;
        uint64_t prevAddr = toAddr - blocklen;
        hashBlocks(state, mem, blocklen, blocklen, fromAddr, prevAddr, toAddr, multiplies, repetitions);
    }
}

// Hash memory with password dependent addressing.
static void hashWithPassword(uint32_t *state, uint32_t *mem, uint32_t p, uint64_t blocklen,
        uint32_t subBlocklen, uint32_t blocksPerThread, uint32_t multiplies, uint32_t repetitions,
        uint32_t parallelism, uint32_t completedBlocks) {

    uint64_t start = blocklen*blocksPerThread*p;

    // Hash one "slice" worth of memory hashing
    for(uint32_t i = completedBlocks; i < completedBlocks + blocksPerThread/TIGERKDF_SLICES; i++) {

        // Compute rand()^3 distance distribution
        uint64_t v = state[0];
        uint64_t v2 = v*v >> 32;
        uint64_t v3 = v*v2 >> 32;
        uint32_t distance = (i-1)*v3 >> 32;

        // Hash the prior block and the block at 'distance' blocks in the past
        uint64_t fromAddr = (i - 1 - distance)*blocklen;

        // Compute which thread's memory to read from
        if(fromAddr < completedBlocks*blocklen) {
            fromAddr += blocklen*(state[1] % parallelism)*blocksPerThread;
        } else {
            fromAddr += start;
        }

        uint64_t toAddr = start + i*blocklen;
        uint64_t prevAddr = toAddr - blocklen;
        hashBlocks(state, mem, blocklen, subBlocklen, fromAddr, prevAddr, toAddr, multiplies, repetitions);
    }
}

// Hash memory for one level of garlic.
static void hashMemory(uint8_t *hash, uint32_t hashSize, uint32_t *mem, uint32_t blocksPerThread, uint32_t blocklen,
        uint32_t subBlocklen, uint32_t multiplies, uint32_t parallelism, uint32_t repetitions) {

    // Convert hash to 8 32-bit ints.
    uint32_t hash256[8];
    hashTo256(hash256, hash, hashSize);
    secureZeroMemory(hash, hashSize);

    // Initialize thread states
    uint32_t state[8*parallelism];
    for(uint32_t p = 0; p < parallelism; p++) {
        hashWithSalt(state + 8*p, hash256, p);
    }

    // Do the the first "resistant" loop in "slices"
    for(uint32_t slice = 0; slice < TIGERKDF_SLICES/2; slice++) {
        for(uint32_t p = 0; p < parallelism; p++) {
            hashWithoutPassword(state + 8*p, mem, p, blocklen, blocksPerThread, multiplies, repetitions,
                parallelism, slice*blocksPerThread/TIGERKDF_SLICES);
        }
    }

    // Do the second "unpredictable" loop in "slices"
    for(uint32_t slice = TIGERKDF_SLICES/2; slice < TIGERKDF_SLICES; slice++) {
        for(uint32_t p = 0; p < parallelism; p++) {
            hashWithPassword(state + 8*p, mem, p, blocklen, subBlocklen, blocksPerThread, multiplies,
                repetitions, parallelism, slice*blocksPerThread/TIGERKDF_SLICES);
        }
    }

    // Apply a crypto-strength hash
    addIntoHash(hash256, mem, parallelism, blocklen, blocksPerThread);
    uint8_t buf[32];
    be32enc_vect(buf, hash256, 32);
    PBKDF2(hash, hashSize, buf, 32, NULL, 0);
}

// The TigerKDF password hashing function.  blocklen should be a multiple of subBlocklen.
// hashSize should be a multiple of 4, and blocklen and subBlocklen should be multiples of 8.
// Return false if there is a memory allocation error.
bool TigerKDF(uint8_t *hash, uint32_t hashSize, uint8_t startMemCost, uint8_t stopMemCost, uint8_t timeCost,
        uint32_t blocklen, uint32_t subBlocklen, uint32_t parallelism, bool updateMemCostMode) {

    // Allocate memory
    uint32_t blocksPerThread = TIGERKDF_SLICES*((1 << stopMemCost)/(TIGERKDF_SLICES*parallelism));
    uint32_t *mem = malloc((uint64_t)blocklen*blocksPerThread*parallelism*sizeof(uint32_t));
    if(mem == NULL) {
        return false;
    }

    // Expand time cost into multiplies and repetitions
    uint32_t multiplies, repetitions;
    if(timeCost <= 8) {
        multiplies = timeCost;
        repetitions = 1;
    } else {
        multiplies = 8;
        repetitions = 1 << (timeCost - 8);
    }

    // Iterate through the levels of garlic.  Throw away some early memory to reduce the
    // danger from leaking memory to an attacker.
    for(uint8_t i = 0; i <= stopMemCost; i++) {
        if(i >= startMemCost || (!updateMemCostMode && i < startMemCost - 6)) {
            blocksPerThread = TIGERKDF_SLICES*((1 << i)/(TIGERKDF_SLICES*parallelism));
            if(blocksPerThread >= TIGERKDF_SLICES) {
                hashMemory(hash, hashSize, mem, blocksPerThread, blocklen, subBlocklen, multiplies,
                    parallelism, repetitions);
            }
        }
    }

    // The light is green, the trap is clean
    //dumpMemory("dieharder_data", mem, (uint64_t)blocklen*blocksPerThread*parallelism);
    free(mem);
    return true;
}
