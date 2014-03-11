/*
   TigerPHS internal header file

   Written in 2014 by Bill Cox <waywardgeek@gmail.com>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include "blake2/blake2.h"

#define TIGERPHS_KEYSIZE 32
#define TIGERPHS_MEMCOST 20 // 1 GiB
#define TIGERPHS_PARALLELISM 2
#define TIGERPHS_BLOCKLEN (16384/sizeof(uint32_t))
#define TIGERPHS_SUBBLOCKLEN (64/sizeof(uint32_t))
#define TIGERPHS_TIMECOST 0
#define TIGERPHS_MULTIPLIES 3
#define TIGERPHS_SLICES 4
#define TIGERPHS_MINBLOCKS 256

// The TigerPHS password hashing function.  Return false if there is a memory allocation error.
bool TigerPHS(uint8_t *hash, uint32_t hashSize, uint8_t startMemCost, uint8_t stopMemCost, uint8_t timeCost,
    uint8_t parallelism, uint8_t multiplies, bool updateMemCostMode);

// Change these next two functions to use a different cryptographic hash function thank Blake2s.

// This is the crytographically strong password hashing function based on Blake2s.
static inline void H(uint8_t *out, uint32_t outlen, const uint8_t *in, uint32_t inlen, const uint8_t *key,
        uint32_t keylen) {
    if(blake2s(out, in, key, outlen, inlen, keylen)) {
        fprintf(stderr, "Error calling blake2s\n");
        exit(1);
    }
}

// These big-endian encode/decode functions were copied from Script's sha.h

static inline void
be32enc(void *pp, uint32_t x)
{
        uint8_t * p = (uint8_t *)pp;

        p[3] = x & 0xff;
        p[2] = (x >> 8) & 0xff;
        p[1] = (x >> 16) & 0xff;
        p[0] = (x >> 24) & 0xff;
}

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static inline void
be32enc_vect(unsigned char *dst, const uint32_t *src, size_t len)
{
	size_t i;

	for (i = 0; i < len / 4; i++)
		be32enc(dst + i * 4, src[i]);
}

static inline uint32_t
be32dec(const void *pp)
{
        const uint8_t *p = (uint8_t const *)pp;

        return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
            ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

/*
 * Decode a big-endian length len vector of (unsigned char) into a length
 * len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
 */
static inline void
be32dec_vect(uint32_t *dst, const unsigned char *src, size_t len)
{
	size_t i;

	for (i = 0; i < len / 4; i++)
		dst[i] = be32dec(src + i * 4);
}

// Perform one crypto-strength hash on a 32-byte state, with a 32-bit salt.
static inline void hashWithSalt(uint32_t out[8], uint32_t in[8], uint32_t salt) {
    uint8_t s[4];
    uint8_t buf[32];
    be32enc(s, salt);
    be32enc_vect(buf, in, 32);
    H(buf, 32, buf, 32, s, 4);
    be32dec_vect(out, buf, 32);
}

// Hash a variable length hash to a 256-bit hash.
static inline void hashTo256(uint32_t hash256[8], uint8_t *hash, uint32_t hashSize) {
    uint8_t buf[32];
    H(buf, 32, hash, hashSize, NULL, 0);
    be32dec_vect(hash256, buf, 32);
}

// Prevents compiler optimizing out memset() -- from blake2-impl.h
static inline void secureZeroMemory(void *v, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)v;
    while(n--) {
        *p++ = 0;
    }
}

void TigerPHS_ComputeSizes(uint8_t memCost, uint8_t timeCost, uint8_t *parallelism, uint32_t *blocklen,
    uint32_t *blocksPerThread);
void TigerPHS_hkdfExtract(uint32_t hash256[8], uint8_t *hash, uint32_t hashSize);
void TigerPHS_hkdfExpand(uint8_t *hash, uint32_t hashSize, uint32_t hash256[8]);
void TigerPHS_hkdf(uint8_t *hash, uint32_t hashSize);
void printHex(char *message, uint8_t *x, int len);
void printState(char *message, uint32_t state[8]);
void dumpMemory(char *fileName, uint32_t *mem, uint64_t memlen);
