// I, Bill Cox, initially copied this file from Catena's src/catena_test_vectors.c in
// 2014, and modified it to call TigerPHS.  It was written by the Catena team and slightly
// changed by me.  It therefore falls under Catena's MIT license.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tigerphs.h"
#include "tigerphs-impl.h"

#define TEST_MEMCOST 10

/*******************************************************************/

void test_output(uint8_t hashlen,
                 uint8_t *pwd,   uint32_t pwdlen,
                 uint8_t *salt,  uint32_t saltlen,
                 uint8_t *data,  uint32_t datalen,
                 uint8_t memCost, uint8_t timeCost,
                 uint8_t multiplies, uint8_t parallelism)
{
    uint8_t hash[hashlen];

    printHex("Password: ",pwd, pwdlen);
    printHex("Salt: ",salt, saltlen);
    printHex("Associated data:", data, datalen);
    printf("memCost:%u timeCost:%u multiplies:%u parallelism:%u\n", memCost, timeCost, multiplies, parallelism);

    if(!TigerPHS_HashPassword(hash, hashlen, pwd, pwdlen, salt, saltlen, data, datalen, memCost, memCost,
            timeCost, multiplies, parallelism, false, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }

    printHex("\nOutput: ", hash, hashlen);
    printf("\n");
}

/*******************************************************************/

void PHC_test(void)
{
    int i;

    printf("****************************************** Test passwords\n");
    for(i=0; i < 256; i++) {
        test_output(TIGERPHS_KEYSIZE, (uint8_t *) &i, 1, NULL, 0, NULL, 0, TEST_MEMCOST, TIGERPHS_TIMECOST,
            TIGERPHS_MULTIPLIES, TIGERPHS_PARALLELISM);
    }
    printf("****************************************** Test salt\n");
    for(i=0; i < 256; i++) {
        test_output(TIGERPHS_KEYSIZE, NULL, 0, (uint8_t *)&i, 1, NULL, 0, TEST_MEMCOST, TIGERPHS_TIMECOST,
            TIGERPHS_MULTIPLIES, TIGERPHS_PARALLELISM);
    }
    printf("****************************************** Test data\n");
    for(i=0; i < 256; i++) {
        test_output(TIGERPHS_KEYSIZE, NULL, 0, NULL, 0, (uint8_t *)&i, 1, TEST_MEMCOST, TIGERPHS_TIMECOST,
            TIGERPHS_MULTIPLIES, TIGERPHS_PARALLELISM);
    }
    printf("****************************************** Test memCost\n");
    for(i=0; i < TEST_MEMCOST; i++) {
        test_output(TIGERPHS_KEYSIZE, NULL, 0, NULL, 0, NULL, 0, i, TIGERPHS_TIMECOST, TIGERPHS_MULTIPLIES,
            TIGERPHS_PARALLELISM);
    }
    printf("****************************************** Test timeCost\n");
    for(i=0; i < 12; i++) {
        test_output(TIGERPHS_KEYSIZE, NULL, 0, NULL, 0, NULL, 0, TEST_MEMCOST, i, TIGERPHS_MULTIPLIES,
            TIGERPHS_PARALLELISM);
    }
    printf("****************************************** Test multiplies\n");
    for(i=0; i <= 8; i++) {
        test_output(TIGERPHS_KEYSIZE, NULL, 0, NULL, 0, NULL, 0, TEST_MEMCOST, TIGERPHS_TIMECOST, i,
            TIGERPHS_PARALLELISM);
    }
    printf("****************************************** Test parallelism\n");
    for(i=1; i < 10; i++) {
        test_output(TIGERPHS_KEYSIZE, NULL, 0, NULL, 0, NULL, 0, TEST_MEMCOST, TIGERPHS_TIMECOST,
            TIGERPHS_MULTIPLIES, i);
    }
    printf("****************************************** Test hashlen\n");
    for(i=4; i < 256; i += 4) {
        test_output(i, NULL, 0, NULL, 0, NULL, 0, TEST_MEMCOST, TIGERPHS_TIMECOST,
            TIGERPHS_MULTIPLIES, TIGERPHS_PARALLELISM);
    }
}

void verifyPasswordUpdate(void) {

    uint8_t hash1[TIGERPHS_KEYSIZE], hash2[TIGERPHS_KEYSIZE];
    if(!TigerPHS_HashPassword(hash1, TIGERPHS_KEYSIZE, (uint8_t *)"password", 8, (uint8_t *)"salt", 4, NULL, 0,
            0, TEST_MEMCOST, TIGERPHS_TIMECOST, TIGERPHS_MULTIPLIES, TIGERPHS_PARALLELISM, false, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }
    for(uint8_t memCost = 0; memCost < TEST_MEMCOST; memCost++) {
        if(!TigerPHS_HashPassword(hash2, TIGERPHS_KEYSIZE, (uint8_t *)"password", 8, (uint8_t *)"salt", 4, NULL, 0,
                0, memCost, TIGERPHS_TIMECOST, TIGERPHS_MULTIPLIES, TIGERPHS_PARALLELISM, false, false)) {
            fprintf(stderr, "Password hashing failed!\n");
            exit(1);
        }
        if(!TigerPHS_UpdatePasswordMemCost(hash2, TIGERPHS_KEYSIZE, memCost + 1, TEST_MEMCOST, TIGERPHS_TIMECOST,
            TIGERPHS_MULTIPLIES, TIGERPHS_PARALLELISM)) {
            fprintf(stderr, "Password hashing failed!\n");
            exit(1);
        }
        if(memcmp(hash1, hash2, TIGERPHS_KEYSIZE)) {
            fprintf(stderr, "Password update got wrong answer!\n");
            exit(1);
        }
    }
}

void verifyClientServer(void) {

    uint8_t hash1[32];
    if(!TigerPHS_ClientHashPassword(hash1, TIGERPHS_KEYSIZE, (uint8_t *)"password", 8, (uint8_t *)"salt", 4,
            (uint8_t *)"data", 4, TEST_MEMCOST, TEST_MEMCOST, TIGERPHS_TIMECOST,
            TIGERPHS_MULTIPLIES, TIGERPHS_PARALLELISM, false, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }
    TigerPHS_ServerHashPassword(hash1, TIGERPHS_KEYSIZE);
    uint8_t hash2[TIGERPHS_KEYSIZE];
    if(!TigerPHS_HashPassword(hash2, TIGERPHS_KEYSIZE, (uint8_t *)"password", 8, (uint8_t *)"salt", 4,
            (uint8_t *)"data", 4, TEST_MEMCOST, TEST_MEMCOST, TIGERPHS_TIMECOST,
            TIGERPHS_MULTIPLIES, TIGERPHS_PARALLELISM, false, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }
    if(memcmp(hash1, hash2, TIGERPHS_KEYSIZE)) {
        fprintf(stderr, "Password client/server got wrong answer!\n");
        exit(1);
    }
}

/*******************************************************************/

int main()
{
    verifyClientServer();
    verifyPasswordUpdate();
    PHC_test();
    return 0;
}
