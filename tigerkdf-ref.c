#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <byteswap.h>
#include "tigerkdf.h"
#include "tigerkdf-impl.h"

// Perform one crypt-strength hash on a 32-byte state.
static inline void hashState(uint32_t state[32]) {
    uint8_t buf[32];
    be32enc_vect(buf, state, 32);
    H(buf, 32, buf, 32, NULL, 0);
    be32dec_vect(state, buf, 32);
}

// Do low-bandwidth multplication hashing.
static void multHash(uint8_t *hash, uint32_t hashSize, uint32_t numblocks, uint32_t repetitions,
        uint32_t *multHashes, uint32_t multipliesPerBlock, uint32_t parallelism) {
    uint8_t s[sizeof(uint32_t)];
    be32enc(s, parallelism);
    uint8_t threadKey[32];
    uint32_t state[8];
    H(threadKey, 32, hash, hashSize, s, sizeof(uint32_t));
    be32dec_vect(state, threadKey, 32);
    uint32_t numMults = 0;
    uint32_t completedMultiplies = 0;
    for(uint32_t i = 0; i < numblocks*2; i++) {
        uint32_t j;
        for(j = 0; j < multipliesPerBlock * repetitions; j += 8) {
            // This is reversible, and will not lose entropy
            state[0] = (state[0]*(state[1] | 1)) ^ (state[2] >> 1);
            state[1] = (state[1]*(state[2] | 1)) ^ (state[3] >> 1);
            state[2] = (state[2]*(state[3] | 1)) ^ (state[4] >> 1);
            state[3] = (state[3]*(state[4] | 1)) ^ (state[5] >> 1);
            state[4] = (state[4]*(state[5] | 1)) ^ (state[6] >> 1);
            state[5] = (state[5]*(state[6] | 1)) ^ (state[7] >> 1);
            state[6] = (state[6]*(state[7] | 1)) ^ (state[0] >> 1);
            state[7] = (state[7]*(state[0] | 1)) ^ (state[1] >> 1);
            numMults += 8;
        }
        // Apply a crypt-strength hash to the state and broadcast the result
        hashState(state);
        for(j = 0; j < 8; j++) {
            multHashes[8*completedMultiplies + j] = state[j];
        }
        completedMultiplies++;
    }
    printf("total multiplies:%u\n", numMults);
}

// Add the last hashed data from each memory thread into the result and apply a
// crypto-strength hash to it.
static void combineHashes(uint8_t *hash, uint32_t hashSize, uint32_t *mem, uint32_t blocklen,
        uint32_t numblocks, uint32_t parallelism) {
    uint8_t data[hashSize];
    for(uint32_t p = 0; p < parallelism; p++) {
        uint64_t pos = 2*(p+1)*numblocks*(uint64_t)blocklen - hashSize/sizeof(uint32_t);
        be32enc_vect(data, mem + pos, hashSize);
        uint32_t i;
        for(i = 0; i < hashSize; i++) {
            hash[i] += data[i];
        }
    }
    H(hash, hashSize, hash, hashSize, NULL, 0);
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
                    state[k] = (state[k] >> 25) | (state[k] << 7);
                    *t++ = state[k];
                }
            }
        }
    }
}

// Hash the multiply chain state into our state.  If the multiplies are falling behind, sleep for a while.
static void hashMultItoState(uint32_t iteration, uint32_t *multHashes, uint32_t *state) {
    for(uint32_t i = 0; i < 8; i++) {
        state[i] ^= multHashes[iteration*8 + i];
    }
    hashState(state);
}

// Bit-reversal function derived from Catena's version.
uint32_t reverse(uint32_t x, const uint8_t n)
{
    if(n == 0) {
        return 0;
    }
    x = bswap_32(x);
    x = ((x & 0x0f0f0f0f) << 4) | ((x & 0xf0f0f0f0) >> 4);
    x = ((x & 0x33333333) << 2) | ((x & 0xcccccccc) >> 2);
    x = ((x & 0x55555555) << 1) | ((x & 0xaaaaaaaa) >> 1);
    return x >> (32 - n);
}

// Hash memory without doing any password dependent memory addressing to thwart cache-timing-attacks.
// Use Solar Designer's sliding-power-of-two window, with Catena's bit-reversal.
static void hashWithoutPassword(uint32_t *mem, uint8_t *hash, uint32_t hashSize, uint32_t p,
        uint32_t blocklen, uint32_t numblocks, uint32_t repetitions, uint32_t *multHashes) {
    uint64_t start = 2*p*(uint64_t)numblocks*blocklen;
    uint8_t threadKey[blocklen*sizeof(uint32_t)];
    uint8_t s[sizeof(uint32_t)];
    be32enc(s, p);
    H(threadKey, blocklen*sizeof(uint32_t), hash, hashSize, s, sizeof(uint32_t));
    be32dec_vect(mem + start, threadKey, blocklen*sizeof(uint32_t));
    uint32_t state[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    uint32_t mask = 1;
    uint32_t numBits = 0;
    uint64_t toAddr = start + blocklen;
    for(uint32_t i = 1; i < numblocks; i++) {
        if(mask << 1 <= i) {
            mask <<= 1;
            numBits++;
        }
        uint32_t reversePos = reverse(i, numBits);
        if(reversePos + mask < i) {
            reversePos += mask;
        }
        uint64_t fromAddr = start + (uint64_t)blocklen*reversePos;
        hashBlocks(state, mem, blocklen, blocklen, fromAddr, toAddr, repetitions);
        hashMultItoState(i, multHashes, state);
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
        hashMultItoState(i, multHashes, state);
        toAddr += blocklen;
    }
}

// The TigerKDF password hashing function.  MemSize is in KiB.
bool TigerKDF(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multipliesPerBlock, uint8_t startGarlic,
        uint8_t stopGarlic, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism, uint32_t repetitions,
        bool skipLastHash) {
    // Compute sizes
    uint64_t memlen = (1 << 10)*(uint64_t)memSize/sizeof(uint32_t);
    uint32_t blocklen = blockSize/sizeof(uint32_t);
    uint32_t numblocks = (memlen/(2*parallelism*blocklen)) << startGarlic;
    uint32_t subBlocklen = subBlockSize != 0? subBlockSize/sizeof(uint32_t) : blocklen;
    memlen = (2*parallelism*(uint64_t)numblocks*blocklen) << (stopGarlic - startGarlic);
    multipliesPerBlock = 8*(multipliesPerBlock/8);
    if(multipliesPerBlock == 0) {
        multipliesPerBlock = 8;
    }
    // Allocate memory
    uint32_t *mem = malloc( memlen*sizeof(uint32_t));
    if(mem == NULL) {
        return false;
    }
    uint32_t *multHashes = (uint32_t *)malloc(8*sizeof(uint32_t)*memlen/blocklen);
    if(multHashes == NULL) {
        return false;
    }
    // Iterate through the levels of garlic
    for(uint8_t i = startGarlic; i <= stopGarlic; i++) {
        // Do the multiplication chains
        multHash(hash, hashSize, numblocks, repetitions, multHashes, multipliesPerBlock, parallelism);
        // Do the the first "pure" loop
        uint32_t p;
        for(p = 0; p < parallelism; p++) {
            hashWithoutPassword(mem, hash, hashSize, p, blocklen, numblocks, repetitions, multHashes);
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
            H(hash, hashSize, hash, hashSize, &i, 1);
        }
    }
    // The light is green, the trap is clean
    free(multHashes);
    free(mem);
    return true;
}
