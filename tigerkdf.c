/*
   TigerKDF optimized C version

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
#include <pthread.h>
#include <byteswap.h>
#include "tigerkdf.h"
#include "tigerkdf-impl.h"

// This include code copied from blake2s.c
#include "blake2/blake2-config.h"

#include <emmintrin.h>
#if defined(HAVE_SSSE3)
#include <tmmintrin.h>
#endif
#if defined(HAVE_SSE41)
#include <smmintrin.h>
#endif
#if defined(HAVE_AVX)
#include <immintrin.h>
#endif
#if defined(HAVE_XOP)
#include <x86intrin.h>
#endif

// This rotate code is motivated from blake2s-round.h
#ifdef __AVX2__
#define DECLARE_ROTATE_CONSTS \
    __m256i shuffleVal = _mm256_set_epi8(30, 29, 28, 31, 26, 25, 24, 27, 22, 21, 20, 23, 18, 17, 16, 19, \
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
#define ROTATE_LEFT8(s) _mm256_shuffle_epi8(s, shuffleVal)
#else
#ifndef HAVE_XOP
#ifdef HAVE_SSSE3
#define DECLARE_ROTATE_CONSTS \
    __m128i shuffleVal = _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
#define ROTATE_LEFT8(s) _mm_shuffle_epi8(s, shuffleVal)
#else
#define DECLARE_ROTATE_CONSTS \
    __m128i shiftRightVal = _mm_set_epi32(24, 24, 24, 24); \
    __m128i shiftLeftVal = _mm_set_epi32(8, 8, 8, 8);
#define ROTATE_LEFT8(s) _mm_or_si128(_mm_srl_epi32(s, shiftRightVal), _mm_sll_epi32(s, shiftLeftVal))
#endif
#else
#define DECLARE_ROTATE_CONSTS
#define ROTATE_LEFT8(s) _mm_roti_epi32(r, 8)
#endif
#endif


// This structure is shared among all threads.
struct TigerKDFCommonDataStruct {
    uint32_t *mem;
    uint32_t *hash256;
    uint32_t parallelism;
    uint32_t blocklen;
    uint32_t subBlocklen;
    uint32_t blocksPerThread;
    uint32_t repetitions;
    uint32_t multiplies;
    uint32_t completedBlocks;
};

// This structure is unique to each memory-hashing thread
struct TigerKDFContextStruct {
    struct TigerKDFCommonDataStruct *common;
    uint32_t state[8];
    uint32_t p; // This is the memory-thread number
};

// Add the last hashed data into the result.
static void addIntoHash(uint32_t *hash256, uint32_t *mem, uint32_t parallelism, uint32_t blocklen,
        uint32_t blocksPerThread) {
    for(uint32_t p = 0; p < parallelism; p++) {
        for(uint32_t i = 0; i < 8; i++) {
            hash256[i] += mem[(p+1)*(uint64_t)blocklen*blocksPerThread + i - 8];
        }
    }
}

#ifdef __AVX2__
static void convStateFromUint32ToM256i(uint32_t state[8], __m256i *v) {
    *v = _mm256_set_epi32(state[7], state[6], state[5], state[4], state[3], state[2], state[1], state[0]);
}

// Convert two __m256i to uint32_t[8].
static void convStateFromM256iToUint32(__m256i *v, uint32_t state[8]) {
    uint32_t *p = (uint32_t *)v;
    uint32_t i;
    for(i = 0; i < 8; i++) {
        state[i] = p[i];
    }
}
#else
// Convert a uint32_t[8] to two __m128i values.
static void convStateFromUint32ToM128i(uint32_t state[8], __m128i *v1, __m128i *v2) {
    *v1 = _mm_set_epi32(state[3], state[2], state[1], state[0]);
    *v2 = _mm_set_epi32(state[7], state[6], state[5], state[4]);
}

// Convert two __m128i to uint32_t[8].
static void convStateFromM128iToUint32(__m128i *v1, __m128i *v2, uint32_t state[8]) {
    uint32_t *p = (uint32_t *)v1;
    uint32_t i;
    for(i = 0; i < 4; i++) {
        state[i] = p[i];
    }
    p = (uint32_t *)v2;
    for(i = 0; i < 4; i++) {
        state[i+4] = p[i];
    }
}
#endif

// Hash three blocks together with fast SSE friendly hash function optimized for high memory bandwidth.
// Basically, it does for every 8 words:
//     for(i = 0; i < 8; i++) {
//         state[i] = ROTATE_LEFT((state[i] + *p++) ^ *f++, 8);
//         *t++ = state[i];
//     
static inline void hashBlocksInner(uint32_t state[8], uint32_t *mem, uint32_t blocklen, uint32_t subBlocklen,
        uint32_t blocksPerThread, uint64_t fromAddr, uint64_t prevAddr, uint64_t toAddr, uint32_t multiplies,
        uint32_t repetitions) {

    // Do SIMD friendly memory hashing and a scalar CPU friendly parallel multiplication chain
    uint32_t numSubBlocks = blocklen/subBlocklen;
    uint32_t oddState[8];
    for(uint32_t i = 0; i < 8; i++) {
        oddState[i] = state[i] | 1;
    }
    int64_t v = 1;

#ifdef __AVX2__
    __m256i s;
    convStateFromUint32ToM256i(state, &s);
    __m256i *m = (__m256i *)mem;
    DECLARE_ROTATE_CONSTS
    __m256i *f;
    __m256i *t;
    __m256i *p;
    for(uint32_t r = 0; r < repetitions-1; r++) {
        f = m + fromAddr/8;
        for(uint32_t i = 0; i < numSubBlocks; i++) {
            uint32_t randVal = *(uint32_t *)f;
            p = m + prevAddr/8 + (subBlocklen/8)*(randVal & (numSubBlocks - 1));
            for(uint32_t j = 0; j < subBlocklen/8; j++) {

                // Compute the multiplication chain
                for(uint32_t k = 0; k < multiplies; k++) {
                    v = (int32_t)v * (int64_t)oddState[k];
                    v ^= randVal;
                    randVal += v >> 32;
                }

                // Hash 32 bytes of memory
                s = _mm256_add_epi32(s, *p++);
                s = _mm256_xor_si256(s, *f++);
                s = ROTATE_LEFT8(s);
            }
        }
    }
    f = m + fromAddr/8;
    t = m + toAddr/8;
    for(uint32_t i = 0; i < numSubBlocks; i++) {
        uint32_t randVal = *(uint32_t *)f;
        p = m + prevAddr/8 + (subBlocklen/8)*(randVal & (numSubBlocks - 1));
        for(uint32_t j = 0; j < subBlocklen/8; j++) {

            // Compute the multiplication chain
            for(uint32_t k = 0; k < multiplies; k++) {
                v = (int32_t)v * (int64_t)oddState[k];
                v ^= randVal;
                randVal += v >> 32;
            }

            // Hash 32 bytes of memory
            s = _mm256_add_epi32(s, *p++);
            s = _mm256_xor_si256(s, *f++);
            s = ROTATE_LEFT8(s);
            *t++ = s;
        }
    }
    convStateFromM256iToUint32(&s, state);
#else
    __m128i s1;
    __m128i s2;
    convStateFromUint32ToM128i(state, &s1, &s2);
    __m128i *m = (__m128i *)mem;
    DECLARE_ROTATE_CONSTS
    __m128i *f;
    __m128i *t;
    __m128i *p;
    for(uint32_t r = 0; r < repetitions-1; r++) {
        f = m + fromAddr/4;
        for(uint32_t i = 0; i < numSubBlocks; i++) {
            uint32_t randVal = *(uint32_t *)f;
            p = m + prevAddr/4 + (subBlocklen/4)*(randVal & (numSubBlocks - 1));
            for(uint32_t j = 0; j < subBlocklen/8; j++) {

                // Compute the multiplication chain
                for(uint32_t k = 0; k < multiplies; k++) {
                    v = (int32_t)v * (int64_t)oddState[k];
                    v ^= randVal;
                    randVal += v >> 32;
                }

                // Hash 32 bytes of memory
                s1 = _mm_add_epi32(s1, *p++);
                s1 = _mm_xor_si128(s1, *f++);
                // Rotate left 8
                s1 = ROTATE_LEFT8(s1);
                s2 = _mm_add_epi32(s2, *p++);
                s2 = _mm_xor_si128(s2, *f++);
                // Rotate left 8
                s2 = ROTATE_LEFT8(s2);
            }
        }
    }
    f = m + fromAddr/4;
    t = m + toAddr/4;
    for(uint32_t i = 0; i < numSubBlocks; i++) {
        uint32_t randVal = *(uint32_t *)f;
        p = m + prevAddr/4 + (subBlocklen/4)*(randVal & (numSubBlocks - 1));
        for(uint32_t j = 0; j < subBlocklen/8; j++) {

            // Compute the multiplication chain

            for(uint32_t k = 0; k < multiplies; k++) {
                v = (int32_t)v * (int64_t)oddState[k];
                v ^= randVal;
                randVal += v >> 32;
            }

            // Hash 32 bytes of memory
            s1 = _mm_add_epi32(s1, *p++);
            s1 = _mm_xor_si128(s1, *f++);
            // Rotate left 8
            s1 = ROTATE_LEFT8(s1);
            *t++ = s1;
            s2 = _mm_add_epi32(s2, *p++);
            s2 = _mm_xor_si128(s2, *f++);
            // Rotate left 8
            s2 = ROTATE_LEFT8(s2);
            *t++ = s2;
        }
    }
    convStateFromM128iToUint32(&s1, &s2, state);
#endif
    hashWithSalt(state, state, v);
}

// This crazy wrapper is simply to force to optimizer to unroll the multiplication loop.
// It only was required for Haswell while running entirely in L1 cache.
static inline void hashBlocks(uint32_t state[8], uint32_t *mem, uint32_t blocklen, uint32_t subBlocklen,
        uint32_t blocksPerThread, uint64_t fromAddr, uint64_t prevAddr, uint64_t toAddr, uint32_t multiplies,
        uint32_t repetitions) {
    switch(multiplies) {
    case 0:
        hashBlocksInner(state, mem, blocklen, subBlocklen, blocksPerThread, fromAddr, prevAddr, toAddr, 0, repetitions);
        break;
    case 1:
        hashBlocksInner(state, mem, blocklen, subBlocklen, blocksPerThread, fromAddr, prevAddr, toAddr, 1, repetitions);
        break;
    case 2:
        hashBlocksInner(state, mem, blocklen, subBlocklen, blocksPerThread, fromAddr, prevAddr, toAddr, 2, repetitions);
        break;
    case 3:
        hashBlocksInner(state, mem, blocklen, subBlocklen, blocksPerThread, fromAddr, prevAddr, toAddr, 3, repetitions);
        break;
    case 4:
        hashBlocksInner(state, mem, blocklen, subBlocklen, blocksPerThread, fromAddr, prevAddr, toAddr, 4, repetitions);
        break;
    case 5:
        hashBlocksInner(state, mem, blocklen, subBlocklen, blocksPerThread, fromAddr, prevAddr, toAddr, 5, repetitions);
        break;
    case 6:
        hashBlocksInner(state, mem, blocklen, subBlocklen, blocksPerThread, fromAddr, prevAddr, toAddr, 6, repetitions);
        break;
    case 7:
        hashBlocksInner(state, mem, blocklen, subBlocklen, blocksPerThread, fromAddr, prevAddr, toAddr, 7, repetitions);
        break;
    case 8:
        hashBlocksInner(state, mem, blocklen, subBlocklen, blocksPerThread, fromAddr, prevAddr, toAddr, 8, repetitions);
        break;
    }
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
static void *hashWithoutPassword(void *contextPtr) {
    struct TigerKDFContextStruct *ctx = (struct TigerKDFContextStruct *)contextPtr;
    struct TigerKDFCommonDataStruct *c = ctx->common;

    uint32_t *state = ctx->state;
    uint32_t *mem = c->mem;
    uint32_t p = ctx->p;
    uint32_t blocklen = c->blocklen;
    uint32_t blocksPerThread = c->blocksPerThread;
    uint32_t multiplies = c->multiplies;
    uint32_t repetitions = c->repetitions;
    uint32_t parallelism = c->parallelism;
    uint32_t completedBlocks = c->completedBlocks;

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

        // Hash the prior block and the block at reversePos and write the result
        uint64_t fromAddr = blocklen*reversePos; // Start for fromAddr is computed in hashBlocks

        // Compute which thread's memory to read from
        if(fromAddr < completedBlocks*blocklen) {
            fromAddr += blocklen*blocksPerThread*(i % parallelism);
        } else {
            fromAddr += start;
        }

        uint64_t toAddr = start + i*blocklen;
        uint64_t prevAddr = toAddr - blocklen;
        hashBlocks(state, mem, blocklen, blocklen, blocksPerThread, fromAddr, prevAddr, toAddr, multiplies, repetitions);
    }
    pthread_exit(NULL);
}

// Hash memory with password dependent addressing.
static void *hashWithPassword(void *contextPtr) {
    struct TigerKDFContextStruct *ctx = (struct TigerKDFContextStruct *)contextPtr;
    struct TigerKDFCommonDataStruct *c = ctx->common;

    uint32_t *state = ctx->state;
    uint32_t *mem = c->mem;
    uint32_t p = ctx->p;
    uint64_t blocklen = c->blocklen;
    uint32_t subBlocklen = c->subBlocklen;
    uint32_t blocksPerThread = c->blocksPerThread;
    uint32_t multiplies = c->multiplies;
    uint32_t repetitions = c->repetitions;
    uint32_t parallelism = c->parallelism;
    uint32_t completedBlocks = c->completedBlocks;

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
        hashBlocks(state, mem, blocklen, subBlocklen, blocksPerThread, fromAddr, prevAddr, toAddr, multiplies, repetitions);
    }
    pthread_exit(NULL);
}

// Hash memory for one level of garlic.
static bool hashMemory(uint8_t *hash, uint32_t hashSize, uint32_t *mem, uint32_t blocksPerThread, uint32_t blocklen,
        uint32_t subBlocklen, uint32_t multiplies, uint32_t parallelism, uint32_t repetitions) {

    // Convert hash to 8 32-bit ints.
    uint32_t hash256[8];
    hashTo256(hash256, hash, hashSize);
    secureZeroMemory(hash, hashSize);

    // Fill out the common constant data used in all threads
    pthread_t memThreads[parallelism];
    struct TigerKDFContextStruct c[parallelism];
    struct TigerKDFCommonDataStruct common;
    common.multiplies = multiplies;
    common.mem = mem;
    common.hash256 = hash256;
    common.blocklen = blocklen;
    common.blocksPerThread = blocksPerThread;
    common.subBlocklen = subBlocklen;
    common.parallelism = parallelism;
    common.repetitions = repetitions;

    // Initialize thread states
    for(uint32_t p = 0; p < parallelism; p++) {
        hashWithSalt(c[p].state, hash256, p);
        c[p].common = &common;
        c[p].p = p;
    }

    // Do the the first "resistant" loop in "slices"
    for(uint32_t slice = 0; slice < TIGERKDF_SLICES/2; slice++) {
        common.completedBlocks = slice*blocksPerThread/TIGERKDF_SLICES;
        for(uint32_t p = 0; p < parallelism; p++) {
            int rc = pthread_create(&memThreads[p], NULL, hashWithoutPassword, (void *)(c + p));
            if(rc) {
                fprintf(stderr, "Unable to start threads\n");
                return false;
            }
        }
        for(uint32_t p = 0; p < parallelism; p++) {
            (void)pthread_join(memThreads[p], NULL);
        }
    }

    // Do the second "unpredictable" loop in "slices"
    for(uint32_t slice = TIGERKDF_SLICES/2; slice < TIGERKDF_SLICES; slice++) {
        common.completedBlocks = slice*blocksPerThread/TIGERKDF_SLICES;
        for(uint32_t p = 0; p < parallelism; p++) {
            int rc = pthread_create(&memThreads[p], NULL, hashWithPassword, (void *)(c + p));
            if(rc) {
                fprintf(stderr, "Unable to start threads\n");
                return false;
            }
        }
        for(uint32_t p = 0; p < parallelism; p++) {
            (void)pthread_join(memThreads[p], NULL);
        }
    }

    // Apply a crypto-strength hash
    addIntoHash(hash256, mem, parallelism, blocklen, blocksPerThread);
    uint8_t buf[32];
    be32enc_vect(buf, hash256, 32);
    PBKDF2(hash, hashSize, buf, 32, NULL, 0);
    return true;
}

// The TigerKDF password hashing function.  blocklen should be a multiple of subBlocklen.
// hashSize should be a multiple of 4, and blocklen and subBlocklen should be multiples of 8.
// Return false if there is a memory allocation error.
bool TigerKDF(uint8_t *hash, uint32_t hashSize, uint8_t startMemCost, uint8_t stopMemCost, uint8_t timeCost,
        uint32_t blocklen, uint32_t subBlocklen, uint32_t parallelism, bool updateMemCostMode) {

    // Allocate memory
    uint32_t blocksPerThread = TIGERKDF_SLICES*((1 << stopMemCost)/(TIGERKDF_SLICES*parallelism));
    uint32_t *mem;
    if(posix_memalign((void *)&mem,  32, (uint64_t)blocklen*blocksPerThread*parallelism*sizeof(uint32_t))) {
        return false;
    }
    if(mem == NULL) {
        return false;
    }

    // Expand time cost into multiplies and repetitions
    uint32_t multiplies, repetitions;
    if(timeCost <= 8) {
        multiplies = timeCost; // Minimizes bandwidth for the given memory size
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
                if(!hashMemory(hash, hashSize, mem, blocksPerThread, blocklen, subBlocklen, multiplies,
                        parallelism, repetitions)) {
                    free(mem);
                    return false;
                }
            }
        }
    }

    // The light is green, the trap is clean
    //dumpMemory("dieharder_data", mem, numblocks*(uint64_t)blocklen);
    free(mem);
    return true;
}
