#include "blake2/blake2.h"
#include "pbkdf2.h"

bool TigerKDF(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multipliesPerBlock, uint8_t startGarlic,
        uint8_t stopGarlic, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism, uint32_t repetitions,
        bool skipLastHash);

void printState(uint32_t state[8]);

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

