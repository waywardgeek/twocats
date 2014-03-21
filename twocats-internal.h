/*
   TwoCats internal header file

   Written in 2014 by Bill Cox <waywardgeek@gmail.com>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <openssl/sha.h>

#if defined(__AVX2__) || defined(__SSE2__)
#include "blake2-sse/blake2.h"
#else
#include "blake2-ref/blake2.h"
#endif

#include "twocats.h"

#define TWOCATS_SLICES 4

// The TwoCats_H wrapper class supports pluggable hash functions.

typedef struct TwoCats_HashStruct TwoCats_H;

struct TwoCats_HashStruct {
    // These three must be defined for each new hash function supported
    union {
        blake2s_state blake2sState;
        blake2b_state blake2bState;
        SHA256_CTX sha256State;
        SHA512_CTX sha512State;
    } c;
    bool (*Init)(TwoCats_H *H);
    bool (*Update)(TwoCats_H *H, const uint8_t *data, uint32_t dataSize);
    bool (*Final)(TwoCats_H *H, uint8_t *hash);
    // These are common to all of them
    bool (*UpdateUint32)(TwoCats_H *H, uint32_t value);
    bool (*Hash)(TwoCats_H *H, uint8_t *hash, uint8_t hashSize);
    bool (*HashState)(TwoCats_H *H, uint32_t *state, uint32_t value);
    bool (*Extract)(TwoCats_H *H, uint32_t *hash32, const uint8_t *hash, uint8_t hashSize);
    bool (*Expand)(TwoCats_H *H, uint8_t *hash, uint8_t hashSize, const uint32_t *hash32);
    bool (*ExpandUint32)(TwoCats_H *H, uint32_t *out, uint32_t outlen, const uint32_t *hash32);
    bool (*FinalUint32)(TwoCats_H *H, uint32_t *hash32);
    char *name;
    TwoCats_HashType type;
    uint8_t size, len; // Size is in bytes, len is in 32-bit ints
};

// These must be provided to support a hash function
void TwoCats_InitBlake2s(TwoCats_H *H);
void TwoCats_InitSHA256(TwoCats_H *H);
void TwoCats_InitBlake2b(TwoCats_H *H);
void TwoCats_InitSHA512(TwoCats_H *H);

void TwoCats_InitHash(TwoCats_H *H, TwoCats_HashType type);

// These big-endian encode/decode functions were copied from Script's sha.h

// Encode a uint32_t as 4 uint8_t's in big-endian order.
static inline void be32enc(uint8_t *p, uint32_t x) {
        p[3] = x;
        p[2] = x >> 8;
        p[1] = x >> 16;
        p[0] = x >> 24;
}

// Encode a length len/4 vector of (uint32_t) into a length len vector of
// (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
static inline void be32enc_vect(uint8_t *dst, const uint32_t *src, uint32_t len) {
    for (uint32_t i = 0; i < len / 4; i++) {
        be32enc(dst + i * 4, src[i]);
    }
}

// Decode 4 uint8_t's in big-endian order to a uint32_t.
static inline uint32_t be32dec(const uint8_t *p) {
    return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
        ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

// Decode a big-endian length len vector of (unsigned char) into a length
// len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
static inline void be32dec_vect(uint32_t *dst, const uint8_t *src, uint32_t len) {
    for(uint32_t i = 0; i < len / 4; i++) {
        dst[i] = be32dec(src + i * 4);
    }
}

// Prevents compiler optimizing out memset() -- from blake2-impl.h
static inline void secureZeroMemory(void *v, uint32_t n) {
    volatile uint8_t *p = (volatile uint8_t *)v;
    while(n--) {
        *p++ = 0;
    }
}

// The TwoCats Internal password hashing function.  Return false if there is a memory allocation error.
bool TwoCats(TwoCats_H *H, uint8_t *hash, uint8_t hashSize, uint8_t startMemCost, uint8_t stopMemCost,
    uint8_t timeCost, uint8_t multiplies, uint8_t lanes, uint8_t parallelism, uint32_t blockSize,
    uint32_t subBlockSize, bool updateMemCostMode);
void TwoCats_ComputeSizes(TwoCats_H *H, uint8_t memCost, uint8_t timeCost, uint8_t *parallelism,
        uint32_t *blocklen, uint32_t *subBlocklen, uint32_t *blocksPerThread);
void TwoCats_PrintState(char *message, uint32_t *state, uint32_t length);
void TwoCats_DumpMemory(char *fileName, uint32_t *mem, uint64_t memlen);
