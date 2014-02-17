#include <stdint.h>
#include <stdbool.h>

// PBKDF2 based hash function.  Uses PBKDF2-SHA256 by default.
void H(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize, uint8_t *salt, uint32_t saltSize);

// This is the prototype required for the password hashing competition.
// t_cost is an integer multiplier on CPU work.  m_cost is an integer number of MiB of memory to hash.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
    unsigned int t_cost, unsigned int m_cost);

// A simple password hashing interface.  MemSize is in MiB.
bool TigerKDF_SimpleHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
    uint8_t *salt, uint32_t saltSize, uint32_t memSize);

// The full password hashing interface.  MemSize is in MiB.
bool TigerKDF_HashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint8_t passwordSize,
    uint8_t *salt, uint32_t saltSize, uint32_t memSize, uint32_t multipliesPerBlock, uint8_t garlic,
    uint8_t *data, uint32_t dataSize, uint32_t blockSize, uint32_t parallelism, uint32_t repetitions);

// Update an existing password hash to a more difficult level of garlic.
bool TigerKDF_UpdatePasswordHash(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multipliesPerBlock,
        uint8_t oldGarlic, uint8_t newGarlic, uint32_t blockSize, uint32_t parallelism, uint32_t repetitions);

// Client-side portion of work for server-relief mode.
bool TigerKDF_ClientHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint8_t passwordSize,
    uint8_t *salt, uint32_t saltSize, uint32_t memSize, uint32_t multipliesPerBlock, uint8_t garlic, uint8_t *data,
    uint32_t dataSize, uint32_t blockSize, uint32_t parallelism, uint32_t repetitions);

// Server portion of work for server-relief mode.
void TigerKDF_ServerHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t garlic);
