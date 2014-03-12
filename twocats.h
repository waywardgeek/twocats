/*
   TwoCats C API header file

   Written in 2014 by Bill Cox <waywardgeek@gmail.com>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdint.h>
#include <stdbool.h>

/*
    For all of these functions, these are the restrictions on sizes:

    hashSize <= 255*32
    startMemCost <= 30
    startMemCost <= stopMemCost <= 30
    oldMemCost < newMemCost <= 30
    timeCost <= 30
    multiplies <= 8
    prallelism <= 255

    NULL values and 0 lengths are legal for all variable sized inputs.
*/


// This is the prototype required for the password hashing competition.
// This is equivalent to !TwoCats_SimpleHashPassword(...)
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen,
    unsigned int t_cost, unsigned int m_cost);

// A simple password hashing interface.  The password is set to 0's.  hashSize must be <= 255*32
bool TwoCats_SimpleHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
    const uint8_t *salt, uint32_t saltSize, uint8_t memCost, uint8_t timeCost);

// The full password hashing interface.  If clearPassword is set, both the password are cleared.
// hashSize must be <= 255*32
bool TwoCats_HashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
    const uint8_t *salt, uint32_t saltSize, uint8_t *data, uint32_t dataSize, uint8_t startMemCost,
    uint8_t stopMemCost, uint8_t timeCost, uint8_t multiplies, uint8_t parallelism,
    bool clearPassword, bool clearData);

// Update an existing password hash to a more difficult level of memCost.
bool TwoCats_UpdatePasswordMemCost(uint8_t *hash, uint32_t hashSize, uint8_t oldMemCost, uint8_t newMemCost,
    uint8_t timeCost, uint8_t multiplies, uint8_t parallelism);

// Client-side portion of work for server-relief mode.  hashSize must be <= 255*32
bool TwoCats_ClientHashPassword(uint8_t *hash, uint32_t hashSize, uint8_t *password, uint32_t passwordSize,
    const uint8_t *salt, uint32_t saltSize, uint8_t *data, uint32_t dataSize, uint8_t startMemCost,
    uint8_t stopMemCost, uint8_t timeCost, uint8_t multiplies, uint8_t parallelism,
    bool clearPassword, bool clearData);

// Server portion of work for server-relief mode.
void TwoCats_ServerHashPassword(uint8_t *hash, uint8_t hashSize);

// Find parameter settings on this machine for a given desired runtime and maximum memory
// usage.  maxMem is in KiB.  Runtime with be typically +/- 50% and memory will be <= maxMem.
void TwoCats_FindCostParameters(uint32_t milliSeconds, uint32_t maxMem, uint8_t *memCost,
    uint8_t *timeCost, uint8_t *multplies);
