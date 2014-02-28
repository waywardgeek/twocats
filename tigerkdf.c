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
#define ROTATE(s) _mm256_shuffle_epi8(s, shuffleVal)
#else
#ifndef HAVE_XOP
#ifdef HAVE_SSSE3
#define DECLARE_ROTATE_CONSTS \
    __m128i shuffleVal = _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);
#define ROTATE(s) _mm_shuffle_epi8(s, shuffleVal)
#else
#define DECLARE_ROTATE_CONSTS \
    __m128i shiftRightVal = _mm_set_epi32(24, 24, 24, 24); \
    __m128i shiftLeftVal = _mm_set_epi32(8, 8, 8, 8);
#define ROTATE(s) _mm_or_si128(_mm_srl_epi32(s, shiftRightVal), _mm_sll_epi32(s, shiftLeftVal))
#endif
#else
#define DECLARE_ROTATE_CONSTS
#define ROTATE(s) _mm_roti_epi32(r, 8)
#endif
#endif


// This structure is shared among all threads.
struct TigerKDFCommonDataStruct {
    uint32_t *mem;
    uint32_t *hash;
    uint32_t parallelism;
    uint32_t blocklen;
    uint32_t subBlocklen;
    uint32_t numblocks;
    uint32_t repetitions;
    uint32_t multiplies;
};

// This structure is unique to each memory-hashing thread
struct TigerKDFContextStruct {
    struct TigerKDFCommonDataStruct *common;
    uint32_t p; // This is the memory-thread number
};


// Add the last hashed data from each memory thread into the result.
static void combineHashes(uint8_t *hash, uint32_t hashSize, uint32_t *mem, uint32_t blocklen, uint32_t numblocks,
        uint32_t parallelism) {
    uint32_t hashlen = hashSize/4;
    uint32_t s[hashlen];
    memset(s, '\0', hashSize);
    for(uint32_t p = 0; p < parallelism; p++) {
        int64_t pos = 2*(p+1)*numblocks*(uint64_t)blocklen - hashlen;
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
        uint64_t fromAddr, uint64_t toAddr, uint32_t multiplies, uint32_t repetitions) {

    uint32_t v = 1;
    uint64_t prevAddr = toAddr - blocklen;
    uint32_t numSubBlocks = blocklen/subBlocklen;
    uint32_t mask = numSubBlocks - 1;
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
            p = m + prevAddr/8 + (subBlocklen/8)*(randVal & mask);
            for(uint32_t j = 0; j < subBlocklen/8; j++) {
                for(uint32_t k = 0; k < multiplies; k++) {
                    v *= randVal | 1;
                    v ^= state[k];
                }
                s = _mm256_add_epi32(s, *p++);
                s = _mm256_xor_si256(s, *f++);
                // Rotate left 8
                s = ROTATE(s);
            }
        }
    }
    f = m + fromAddr/8;
    t = m + toAddr/8;
    for(uint32_t i = 0; i < numSubBlocks; i++) {
        uint32_t randVal = *(uint32_t *)f;
        p = m + prevAddr/8 + (subBlocklen/8)*(randVal & mask);
        for(uint32_t j = 0; j < subBlocklen/8; j++) {
            for(uint32_t k = 0; k < multiplies; k++) {
                v *= randVal | 1;
                v ^= state[k];
            }
            s = _mm256_add_epi32(s, *p++);
            s = _mm256_xor_si256(s, *f++);
            // Rotate left 8
            s = ROTATE(s);
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
            p = m + prevAddr/4 + (subBlocklen/4)*(randVal & mask);
            for(uint32_t j = 0; j < subBlocklen/8; j++) {
                for(uint32_t k = 0; k < multiplies; k++) {
                    v *= randVal | 1;
                    v ^= state[k];
                }
                s1 = _mm_add_epi32(s1, *p++);
                s1 = _mm_xor_si128(s1, *f++);
                // Rotate left 8
                s1 = ROTATE(s1);
                s2 = _mm_add_epi32(s2, *p++);
                s2 = _mm_xor_si128(s2, *f++);
                // Rotate left 8
                s2 = ROTATE(s2);
            }
        }
    }
    f = m + fromAddr/4;
    t = m + toAddr/4;
    for(uint32_t i = 0; i < numSubBlocks; i++) {
        uint32_t randVal = *(uint32_t *)f;
        p = m + prevAddr/4 + (subBlocklen/4)*(randVal & mask);
        for(uint32_t j = 0; j < subBlocklen/8; j++) {
            for(uint32_t k = 0; k < multiplies; k++) {
                v *= randVal | 1;
                v ^= state[k];
            }
            s1 = _mm_add_epi32(s1, *p++);
            s1 = _mm_xor_si128(s1, *f++);
            // Rotate left 8
            s1 = ROTATE(s1);
            *t++ = s1;
            s2 = _mm_add_epi32(s2, *p++);
            s2 = _mm_xor_si128(s2, *f++);
            // Rotate left 8
            s2 = ROTATE(s2);
            *t++ = s2;
        }
    }
    convStateFromM128iToUint32(&s1, &s2, state);
#endif
    state[0] += v;
}

// This crazy wrapper is simply to force to optimizer to unroll the multiplication loop.
// It only was required for Haswell while running entirely in L1 cache.
static void hashBlocks(uint32_t state[8], uint32_t *mem, uint32_t blocklen, uint32_t subBlocklen,
        uint64_t fromAddr, uint64_t toAddr, uint32_t multiplies, uint32_t repetitions) {
    switch(multiplies) {
    case 0:
        hashBlocksInner(state, mem, blocklen, subBlocklen, fromAddr, toAddr, 0, repetitions);
        break;
    case 1:
        hashBlocksInner(state, mem, blocklen, subBlocklen, fromAddr, toAddr, 1, repetitions);
        break;
    case 2:
        hashBlocksInner(state, mem, blocklen, subBlocklen, fromAddr, toAddr, 2, repetitions);
        break;
    case 3:
        hashBlocksInner(state, mem, blocklen, subBlocklen, fromAddr, toAddr, 3, repetitions);
        break;
    case 4:
        hashBlocksInner(state, mem, blocklen, subBlocklen, fromAddr, toAddr, 4, repetitions);
        break;
    case 5:
        hashBlocksInner(state, mem, blocklen, subBlocklen, fromAddr, toAddr, 5, repetitions);
        break;
    case 6:
        hashBlocksInner(state, mem, blocklen, subBlocklen, fromAddr, toAddr, 6, repetitions);
        break;
    case 7:
        hashBlocksInner(state, mem, blocklen, subBlocklen, fromAddr, toAddr, 7, repetitions);
        break;
    case 8:
        hashBlocksInner(state, mem, blocklen, subBlocklen, fromAddr, toAddr, 8, repetitions);
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

    uint32_t *mem = c->mem;
    uint32_t *hash = c->hash;
    uint32_t p = ctx->p;
    uint32_t blocklen = c->blocklen;
    uint32_t numblocks = c->numblocks;
    uint32_t multiplies = c->multiplies;
    uint32_t repetitions = c->repetitions;

    uint32_t state[8];
    hashWithSalt(state, hash, p);
    uint64_t start = 2*p*(uint64_t)numblocks*blocklen;
    for(uint32_t i = 0; i < blocklen/8; i++) {
        hashWithSalt(mem + start + i*8, state, i);
    }
    uint32_t mask = 1;
    uint32_t numBits = 0;
    uint64_t toAddr = start + blocklen;
    for(uint32_t i = 1; i < numblocks; i++) {
        if(mask << 1 <= i) {
            uint64_t first = (toAddr - start)/16;
            uint64_t size = first;
            if((numBits & 0x3) == 0) {
                first = 0;
                size = (toAddr - start)/8;
            }
            numBits++;
            mask <<= 1;
            // Overwrite early memory to hamper leaked memory attacks
            printf("i:%u numBits:%u at %lu Overwriting %lu - %lu\n", i, numBits, toAddr*4,
                first*4, (first + size)*4);
            memcpy(mem + start + first, mem + toAddr - size, size*sizeof(uint32_t));
        }
        uint32_t reversePos = reverse(i, numBits);
        if(reversePos + mask < i) {
            reversePos += mask;
        }
        uint64_t fromAddr = start + (uint64_t)blocklen*reversePos;
        hashBlocks(state, mem, blocklen, blocklen, fromAddr, toAddr, multiplies, repetitions);
        hashWithSalt(state, state, i);
        toAddr += blocklen;
    }
    pthread_exit(NULL);
}

// Hash memory with dependent memory addressing to thwart TMTO attacks.
static void *hashWithPassword(void *contextPtr) {
    struct TigerKDFContextStruct *ctx = (struct TigerKDFContextStruct *)contextPtr;
    struct TigerKDFCommonDataStruct *c = ctx->common;

    uint32_t *mem = c->mem;
    uint32_t parallelism = c->parallelism;
    uint32_t p = ctx->p;
    uint32_t blocklen = c->blocklen;
    uint32_t subBlocklen = c->subBlocklen;
    uint32_t numblocks = c->numblocks;
    uint32_t multiplies = c->multiplies;
    uint32_t repetitions = c->repetitions;

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
    pthread_exit(NULL);
}

// The TigerKDF password hashing function.  MemSize is in KiB.
bool TigerKDF(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multiplies, uint8_t startGarlic,
        uint8_t stopGarlic, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism, uint32_t repetitions,
        bool serverReliefMode) {
    // Compute sizes
    uint64_t memlen = (1 << 10)*(uint64_t)memSize/sizeof(uint32_t);
    uint32_t blocklen = blockSize/sizeof(uint32_t);
    uint32_t numblocks = (memlen/(2*parallelism*blocklen)) << startGarlic;
    memlen = (2*parallelism*(uint64_t)numblocks*blocklen) << (stopGarlic - startGarlic);
    // Allocate memory
    uint32_t *mem;
    if(posix_memalign((void *)&mem,  32, memlen*sizeof(uint32_t))) {
        return false;
    }
    pthread_t *memThreads = (pthread_t *)malloc(parallelism*sizeof(pthread_t));
    if(memThreads == NULL) {
        return false;
    }
    struct TigerKDFContextStruct *c = (struct TigerKDFContextStruct *)malloc(
            parallelism*sizeof(struct TigerKDFContextStruct));
    if(c == NULL) {
        return false;
    }
    struct TigerKDFCommonDataStruct common;
    // Fill out the common constant data used in all threads
    uint32_t hash256[8];
    common.multiplies = multiplies;
    common.hash = hash256;
    common.mem = mem;
    common.blocklen = blocklen;
    common.subBlocklen = subBlockSize != 0? subBlockSize/sizeof(uint32_t) : blocklen;
    common.parallelism = parallelism;
    common.multiplies = multiplies;
    common.repetitions = repetitions;
    // Iterate through the levels of garlic
    for(uint8_t i = startGarlic; i <= stopGarlic; i++) {
        hashTo256(hash256, hash, hashSize);
        common.numblocks = numblocks;
        // Start the memory threads for the first "pure" loop
        uint32_t p;
        for(p = 0; p < parallelism; p++) {
            c[p].common = &common;
            c[p].p = p;
            int rc = pthread_create(&memThreads[p], NULL, hashWithoutPassword, (void *)(c + p));
            if(rc) {
                fprintf(stderr, "Unable to start threads\n");
                return false;
            }
        }
        for(p = 0; p < parallelism; p++) {
            (void)pthread_join(memThreads[p], NULL);
        }
        // Start the memory threads for the second "dirty" loop
        for(p = 0; p < parallelism; p++) {
            int rc = pthread_create(&memThreads[p], NULL, hashWithPassword, (void *)(c + p));
            if(rc) {
                fprintf(stderr, "Unable to start threads\n");
                return false;
            }
        }
        for(p = 0; p < parallelism; p++) {
            (void)pthread_join(memThreads[p], NULL);
        }
        // Combine all the memory thread hashes with a crypto-strength hash
        combineHashes(hash, hashSize, mem, blocklen, numblocks, parallelism);
        PBKDF2(hash, hashSize, hash, hashSize, NULL, 0);
        if(i < stopGarlic || !serverReliefMode) {
            // For server relief mode, skip doing this last hash
            PBKDF2(hash, hashSize, hash, hashSize, NULL, 0);
        }
        // Double the memory for the next round of garlic
        numblocks *= 2;
    }
    // The light is green, the trap is clean
    free(c);
    free(memThreads);
    free(mem);
    return true;
}
