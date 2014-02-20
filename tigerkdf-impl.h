#include "blake2/blake2.h"
#include "pbkdf2.h"

bool TigerKDF(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multipliesPerKB, uint8_t startGarlic,
        uint8_t stopGarlic, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism, uint32_t repetitions,
        bool skipLastHash);

// Change these next two functions to use a different cryptographic hash function thank Blake2s.

// This is the crytographically strong password hashing function based on Blake2s.
static inline void H(uint8_t *out, uint32_t outlen, const uint8_t *in, uint32_t inlen, const uint8_t *key,
        uint32_t keylen) {
    if(outlen < BLAKE2S_OUTBYTES) {
        if(blake2s(out, in, key, outlen, inlen, keylen)) {
            fprintf(stderr, "Error in blake2s\n");
            exit(1);
        }
    } else {
        if(blake2s(out, in, key, BLAKE2S_OUTBYTES, inlen, keylen)) {
            fprintf(stderr, "Error in blake2s\n");
            exit(1);
        }
        uint32_t i;
        for(i = BLAKE2S_OUTBYTES; i < outlen; i += BLAKE2S_OUTBYTES) {
            uint8_t length = i + BLAKE2S_OUTBYTES <= outlen? BLAKE2S_OUTBYTES : outlen - i;
            if(blake2s(out + i, out + i - BLAKE2S_OUTBYTES, NULL, length, BLAKE2S_OUTBYTES, 0)) {
                fprintf(stderr, "Error in blake2s\n");
                exit(1);
            }
        }
    }
}

// This is a PBKDF2 password hashing function based currently on Blake2s
static inline void PBKDF2(uint8_t *hash, uint32_t hashSize, const uint8_t *password, uint32_t passwordSize,
        const uint8_t *salt, uint32_t saltSize) {
    PBKDF2_BLAKE2S(password, passwordSize, salt, saltSize, 1, hash, hashSize);
}

// Perform one crypt-strength hash on a 32-byte state.
static inline void hashState(uint32_t state[8]) {
    uint8_t buf[32];
    be32enc_vect(buf, state, 32);
    H(buf, 32, buf, 32, NULL, 0);
    be32dec_vect(state, buf, 32);
}

// Perform one crypt-strength hash on a 32-byte state, with a 32-bit salt.
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

// Hash a 256-bit hash into a variable length hash.
static inline void hashFrom256(uint8_t *hash, uint32_t hashSize, uint32_t hash256[8]) {
    uint8_t buf[32];
    be32enc_vect(buf, hash256, 32);
    H(hash, hashSize, buf, 32, NULL, 0);
}

void printHex(char *message, uint8_t *x, int len);
void printState(char *message, uint32_t state[8]);
