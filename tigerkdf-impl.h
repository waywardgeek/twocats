/*
   TigerKDF internal header file

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
#include "pbkdf2.h"

bool TigerKDF(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multipliesPerKB, uint8_t startGarlic,
        uint8_t stopGarlic, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism, uint32_t repetitions,
        bool skipLastHash);

// Change these next two functions to use a different cryptographic hash function thank Blake2s.

// This is the crytographically strong password hashing function based on Blake2s.
static inline void H(uint8_t *out, uint32_t outlen, const uint8_t *in, uint32_t inlen, const uint8_t *key,
        uint32_t keylen) {
    if(blake2s(out, in, key, outlen, inlen, keylen)) {
        fprintf(stderr, "Error calling blake2s\n");
        exit(1);
    }
}

// This is a PBKDF2 password hashing function based on Blake2s.
static inline void PBKDF2(uint8_t *hash, uint32_t hashSize, const uint8_t *password, uint32_t passwordSize,
        const uint8_t *salt, uint32_t saltSize) {
    PBKDF2_BLAKE2S(password, passwordSize, salt, saltSize, 1, hash, hashSize);
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

void printHex(char *message, uint8_t *x, int len);
void printState(char *message, uint32_t state[8]);
