#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "../blake2-ref/blake2.h"
#include "skinnycat.h"

#define BLOCKLEN 4096

// Print the hash value in hex.
static void printHex(char *message, uint8_t hash[32]) {
    printf("%s", message);
    for(uint32_t i = 0; i < 32; i++) {
        printf(" %02x", hash[i]);
    }
    printf("\n");
}

// Encode a length len/4 vector of (uint32_t) into a length len vector of
// (unsigned char) in little-endian form.  Assumes len is a multiple of 4.
static inline void encodeLittleEndian(uint8_t *dst, const uint32_t *src, uint32_t len) {
    uint8_t *p = dst;
    for (uint32_t i = 0; i < len / 4; i++) {
        *p++ = *src;
        *p++ = *src >> 8;
        *p++ = *src >> 16;
        *p++ = *src++ >> 24;
    }
}

// Decode a little-endian length len vector of (unsigned char) into a length
// len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
static inline void decodeLittleEndian(uint32_t *dst, const uint8_t *src, uint32_t len) {
    const uint8_t *p = src;
    for(uint32_t i = 0; i < len / 4; i++) {
        dst[i] = ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) + ((uint32_t)(p[2]) << 16) +
            ((uint32_t)(p[3]) << 24));
        p += 4;
    }
}

// Hash the data with a secure hash function.
static bool H(SkinnyCat_HashType hashType, uint8_t out[32], const uint8_t *in, uint32_t inSize) {
    switch(hashType) {
    case SKINNYCAT_BLAKE2S:
        return !blake2s(out, in, NULL, 32, inSize, 0);
    case SKINNYCAT_SHA256:
        return SHA256(in, inSize, out) != NULL;
    default:
        fprintf(stderr, "Unknown hash type\n");
    }
    return false;
}

// Hash between lanes with the secure hash function.
static void hashState(SkinnyCat_HashType hashType, uint32_t out[8], uint32_t in[8], uint32_t a) {
    uint8_t inBuf[36];
    uint8_t outBuf[32];
    encodeLittleEndian(inBuf, in, 32);
    encodeLittleEndian(inBuf + 32, &a, 4);
    H(hashType, outBuf, inBuf, 36);
    decodeLittleEndian(out, outBuf, 32);
}

// Fill memmory with pseudo-random data using H.
static void expand(SkinnyCat_HashType hashType, uint32_t *mem, uint32_t len, uint32_t state[8]) {
    for(uint32_t count = 0; count < len/8; count++) {
        hashState(hashType, mem + count*8, state, count);
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

// Find the sliding reverse position of the prior block.
static uint32_t slidingReverse(uint32_t i) {
    uint32_t numBits = 1;
    while((1 << numBits) <= i) {
        numBits++;
    }
    uint32_t reversePos = reverse(i, numBits-1);
    if(reversePos + (1 << (numBits-1)) < i) {
        reversePos += 1 << (numBits-1);
    }
    return reversePos;
}

// Find the distance to the prior block using a cubed distribution.
static uint32_t distanceCubed(uint32_t i, uint64_t v) {
    uint64_t v2 = v*v >> 32;
    uint64_t v3 = v*v2 >> 32;
    return (i-1)*v3 >> 32;
}

// Add the last hashed data into the result.
static void addIntoHash(uint32_t *hash32, uint32_t *states) {
    for(uint32_t i = 0; i < 8; i++) {
        hash32[i] += states[i];
    }
}

bool SkinnyCat_HashPassword(SkinnyCat_HashType hashType, uint8_t *hash, uint8_t *password,
        uint8_t passwordSize, const uint8_t *salt, uint8_t saltSize, uint8_t memCost,
        bool clearPassword) {
    
    // Adjust block length to something sane for small memory
    uint32_t blocklen = BLOCKLEN;
    if(blocklen > 4 << memCost) {
        blocklen = 4 << memCost;
    }

    // Derive pseudorandom key from password and salt
    uint32_t state[8], hash32[8];
    uint32_t tweakSize = 6*sizeof(uint32_t) + 6 + saltSize + passwordSize;
    uint32_t data32[6] = {32, passwordSize, saltSize, 0, blocklen, blocklen};
    uint8_t data8[6] = {memCost, 0, 0, 8, 1, 0};
    uint8_t tweak[tweakSize];
    encodeLittleEndian(tweak, data32, 24);
    memcpy(tweak + 24, data8, 6);
    memcpy(tweak + 30, password, passwordSize);
    memcpy(tweak + 30 + passwordSize, salt, saltSize);
    uint8_t buf[32];
    H(hashType, buf, tweak, tweakSize);

    H(hashType, buf, buf, 32); // One more for compatibility with TwoCats
    decodeLittleEndian(hash32, buf, 32);
    memcpy(state, hash32, 32);

    if(clearPassword) {
        memset(password, 0, passwordSize);
    }

    uint64_t memlen = (1024ull << memCost)/sizeof(uint32_t);
    uint32_t *mem = malloc(memlen*sizeof(uint32_t));
    if(mem == NULL) {
        return false;
    }

    expand(hashType, mem, blocklen, state);
    uint64_t prevAddr = 0;
    uint64_t toAddr = BLOCKLEN;
    for(uint32_t i = 1; i < memlen/(2*BLOCKLEN); i++) {
        uint32_t a = state[0]; // For compatibility with TwoCats
        uint64_t fromAddr = slidingReverse(i)*BLOCKLEN;
        for(uint32_t j = 0; j < BLOCKLEN/8; j++) {
            for(uint32_t k = 0; k < 8; k++) {
                state[k] = (state[k] + mem[prevAddr++]) ^ mem[fromAddr++];
                state[k] = (state[k] >> 24) | (state[k] << 8);
                mem[toAddr++] = state[k];
            }
        }
        hashState(hashType, state, state, a);
    }
    for(uint32_t i = memlen/(2*BLOCKLEN); i < memlen/BLOCKLEN; i++) {
        uint32_t a = state[0]; // For compatibility with TwoCats
        uint64_t fromAddr = (i - 1 - distanceCubed(i, state[0]))*BLOCKLEN;
        for(uint32_t j = 0; j < BLOCKLEN/8; j++) {
            for(uint32_t k = 0; k < 8; k++) {
                state[k] = (state[k] + mem[prevAddr++]) ^ mem[fromAddr++];
                state[k] = (state[k] >> 24) | (state[k] << 8);
                mem[toAddr++] = state[k];
            }
        }
        hashState(hashType, state, state, a);
    }
    addIntoHash(hash32, state);
    encodeLittleEndian(hash, hash32, 32);
    H(hashType, hash, hash, 32); // One more for compatibility with TwoCats
    return true;
}

int main(int argc, char **argv) {
    uint8_t memCost = 20;
    if(argc > 2) {
        fprintf(stderr, "Usage: skinnycat [memCost]\n");
        return 1;
    } else if(argc == 1) {
        memCost = atoi(argv[1]);
    }
    uint8_t hash[32];
    SkinnyCat_HashPassword(SKINNYCAT_BLAKE2S, hash, (uint8_t *)"password", 8, (uint8_t *)"salt", 4, memCost, false);
    printHex("result:", hash);
    return 0;
}
