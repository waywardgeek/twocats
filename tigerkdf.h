/*
   TigerKDF C API header file

   Written in 2014 by Bill Cox <waywardgeek@gmail.com>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdint.h>
#include <stdbool.h>

// This is the prototype required for the password hashing competition.
// t_cost is a multiplier on CPU work.  m_cost is the number of KiB of memory to hash.
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
    unsigned int t_cost, unsigned int m_cost);

// A simple password hashing interface.  MemSize is in KiB.  The password is set to 0's.
bool TigerKDF_SimpleHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
    const uint8_t *salt, uint32_t saltSize, uint32_t memSize);

// The full password hashing interface.  MemSize is in KiB.  If clearPassword is set, both
// the password and data, if not NULL, are cleared;
bool TigerKDF_HashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint8_t passwordSize,
    const uint8_t *salt, uint32_t saltSize, uint32_t memSize, uint32_t multipliesPerKB, uint8_t garlic,
    uint8_t *data, uint32_t dataSize, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism,
    uint32_t repetitions, bool clearPassword);

// Update an existing password hash to a more difficult level of garlic.
bool TigerKDF_UpdatePasswordHash(uint8_t *hash, uint32_t hashSize, uint32_t memSize, uint32_t multipliesPerKB,
        uint8_t oldGarlic, uint8_t newGarlic, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism,
        uint32_t repetitions);

// Client-side portion of work for server-relief mode.  The final call to H is not made.
bool TigerKDF_ClientHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint8_t passwordSize,
    const uint8_t *salt, uint32_t saltSize, uint32_t memSize, uint32_t multipliesPerKB, uint8_t garlic,
    uint8_t *data, uint32_t dataSize, uint32_t blockSize, uint32_t subBlockSize, uint32_t parallelism,
    uint32_t repetitions, bool clearPassword);

// Server portion of work for server-relief mode.  It simply calls H once.
void TigerKDF_ServerHashPassword(uint8_t *hash, uint32_t hashSize);

// Find a good set of parameters for this machine based on a desired hashing time and
// maximum memory.  maxTime is in microseconds, and maxMem is in KiB.
uint32_t TigerKDF_GuessParameters(uint32_t maxTime, uint32_t maxMem, uint32_t maxParallelism, uint32_t *memSize,
    uint32_t *multipliesPerKB, uint32_t *parallelism, uint32_t *repetitions);
