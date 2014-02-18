#include <stdint.h>
#include <stdbool.h>
#include "blake2/blake2.h"
#include "pbkdf2.h"

// This is the prototype required for the password hashing competition.
// t_cost is an integer multiplier on CPU work.  m_cost is an integer number of KiB of memory to hash.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
    unsigned int t_cost, unsigned int m_cost);

// Change these next two functions to use a different cryptographic hash function thank Blake2s.

// This is the crytographically strong password hashing function based on Blake2s.
static inline void H(uint8_t *out, uint32_t outlen, const uint8_t *in, uint32_t inlen, const uint8_t *key,
        uint32_t keylen) {
    if(outlen < BLAKE2S_OUTBYTES) {
        if(blake2s(out, in, key, outlen, inlen, keylen)) {
            printf("Error in blake2s\n");
            exit(1);
        }
    } else {
        if(blake2s(out, in, key, BLAKE2S_OUTBYTES, inlen, keylen)) {
            printf("Error in blake2s\n");
            exit(1);
        }
        uint32_t i;
        for(i = BLAKE2S_OUTBYTES; i < outlen; i += BLAKE2S_OUTBYTES) {
            uint8_t length = i + BLAKE2S_OUTBYTES <= outlen? BLAKE2S_OUTBYTES : outlen - i;
            if(blake2s(out + i, out + i - BLAKE2S_OUTBYTES, NULL, length, BLAKE2S_OUTBYTES, 0)) {
                printf("Error in blake2s\n");
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

// A simple password hashing interface.  MemSize is in KiB.  The password is set to 0's.
bool TigerKDF_SimpleHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
    const uint8_t *salt, uint32_t saltSize, uint32_t memSize);

// The full password hashing interface.  MemSize is in KiB.  If clearPassword is set, both
// the password and data, if not NULL, are cleared;
bool TigerKDF_HashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint8_t passwordSize,
    const uint8_t *salt, uint32_t saltSize, uint32_t memSize, uint32_t multipliesPerBlock, uint8_t garlic,
    uint8_t *data, uint32_t dataSize, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism,
    uint32_t repetitions, bool clearPassword);

// Find a good set of parameters for this machine based on a desired hashing time and
// maximum memory.  maxTime is in microseconds, and maxMem is in KiB.
uint32_t TigerKDF_GuessParameters(uint32_t maxTime, uint32_t maxMem, uint32_t *memSize, uint32_t *multipliesPerBlock,
    uint32_t *blockSize, uint32_t *parallelism, uint32_t *repetitions);

// Update an existing password hash to a more difficult level of garlic.
bool TigerKDF_UpdatePasswordHash(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multipliesPerBlock,
        uint8_t oldGarlic, uint8_t newGarlic, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism,
        uint32_t repetitions);

// Client-side portion of work for server-relief mode.  The final call to H is not made.
bool TigerKDF_ClientHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint8_t passwordSize,
    const uint8_t *salt, uint32_t saltSize, uint32_t memSize, uint32_t multipliesPerBlock, uint8_t garlic,
    uint8_t *data, uint32_t dataSize, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism,
    uint32_t repetitions, bool clearPassword);

// Server portion of work for server-relief mode.  It simply calls H once.
void TigerKDF_ServerHashPassword(uint8_t *hash, uint32_t hashSize);
