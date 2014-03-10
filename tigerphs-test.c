// I, Bill Cox, initially copied this file from Catena's src/catena_test_vectors.c in
// 2014, and modified it to call TigerKDF.  It was written by the Catena team and slightly
// changed by me.  It therefore falls under Catena's MIT license.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tigerkdf.h"
#include "tigerkdf-impl.h"

#define TEST_MEMCOST 10

/*******************************************************************/

void test_output(uint8_t hashlen,
                 uint8_t *pwd,   uint32_t pwdlen,
                 uint8_t *salt,  uint8_t saltlen,
                 uint8_t *data,  uint32_t datalen,
                 uint8_t memCost, uint8_t timeCost,
                 uint32_t parallelism)
{
    uint8_t hash[hashlen];

    printHex("Password: ",pwd, pwdlen);
    printHex("Salt: ",salt, saltlen);
    printHex("Associated data:", data, datalen);
    printf("memCost:%u timeCost:%u parallelism:%u\n", memCost, timeCost, parallelism);

    if(!TigerKDF_HashPassword(hash, hashlen, pwd, pwdlen, salt, saltlen, data, datalen, memCost, memCost,
            timeCost, parallelism, false)) {
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
        test_output(TIGERKDF_KEYSIZE, (uint8_t *) &i, 1, NULL, 0, NULL, 0, TEST_MEMCOST, TIGERKDF_TIMECOST,
            TIGERKDF_PARALLELISM);
    }
    printf("****************************************** Test salt\n");
    for(i=0; i < 256; i++) {
        test_output(TIGERKDF_KEYSIZE, NULL, 0, (uint8_t *)&i, 1, NULL, 0, TEST_MEMCOST, TIGERKDF_TIMECOST,
            TIGERKDF_PARALLELISM);
    }
    printf("****************************************** Test data\n");
    for(i=0; i < 256; i++) {
        test_output(TIGERKDF_KEYSIZE, NULL, 0, NULL, 0, (uint8_t *)&i, 1, TEST_MEMCOST, TIGERKDF_TIMECOST,
            TIGERKDF_PARALLELISM);
    }
    printf("****************************************** Test memCost\n");
    for(i=0; i < TEST_MEMCOST; i++) {
        test_output(TIGERKDF_KEYSIZE, NULL, 0, NULL, 0, NULL, 0, i, TIGERKDF_TIMECOST, TIGERKDF_PARALLELISM);
    }
    printf("****************************************** Test timeCost\n");
    for(i=0; i < 12; i++) {
        test_output(TIGERKDF_KEYSIZE, NULL, 0, NULL, 0, NULL, 0, TEST_MEMCOST, i, TIGERKDF_PARALLELISM);
    }
    printf("****************************************** Test parallelism\n");
    for(i=1; i < 10; i++) {
        test_output(TIGERKDF_KEYSIZE, NULL, 0, NULL, 0, NULL, 0, TEST_MEMCOST, TIGERKDF_TIMECOST, i);
    }
    printf("****************************************** Test hashlen\n");
    for(i=4; i < 256; i += 4) {
        test_output(i, NULL, 0, NULL, 0, NULL, 0, TEST_MEMCOST, TIGERKDF_TIMECOST, TIGERKDF_PARALLELISM);
    }
}

void verifyPasswordUpdate(void) {

    uint8_t hash1[TIGERKDF_KEYSIZE], hash2[TIGERKDF_KEYSIZE];
    if(!TigerKDF_HashPassword(hash1, TIGERKDF_KEYSIZE, (uint8_t *)"password", 8, (uint8_t *)"salt", 4, NULL, 0,
            0, TEST_MEMCOST, TIGERKDF_TIMECOST, TIGERKDF_PARALLELISM, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }
    for(uint8_t memCost = 0; memCost < TEST_MEMCOST; memCost++) {
        if(!TigerKDF_HashPassword(hash2, TIGERKDF_KEYSIZE, (uint8_t *)"password", 8, (uint8_t *)"salt", 4, NULL, 0,
                0, memCost, TIGERKDF_TIMECOST, TIGERKDF_PARALLELISM, false)) {
            fprintf(stderr, "Password hashing failed!\n");
            exit(1);
        }
        if(!TigerKDF_UpdatePasswordMemCost(hash2, TIGERKDF_KEYSIZE, memCost + 1, TEST_MEMCOST, TIGERKDF_TIMECOST,
            TIGERKDF_PARALLELISM)) {
            fprintf(stderr, "Password hashing failed!\n");
            exit(1);
        }
        if(memcmp(hash1, hash2, TIGERKDF_KEYSIZE)) {
            fprintf(stderr, "Password update got wrong answer!\n");
            exit(1);
        }
    }
}

void verifyClientServer(void) {

    uint8_t hash1[32];
    if(!TigerKDF_ClientHashPassword(hash1, TIGERKDF_KEYSIZE, (uint8_t *)"password", 8, (uint8_t *)"salt", 4,
            (uint8_t *)"data", 4, TEST_MEMCOST, TEST_MEMCOST, TIGERKDF_TIMECOST, TIGERKDF_PARALLELISM, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }
    TigerKDF_ServerHashPassword(hash1, TIGERKDF_KEYSIZE);
    uint8_t hash2[TIGERKDF_KEYSIZE];
    if(!TigerKDF_HashPassword(hash2, TIGERKDF_KEYSIZE, (uint8_t *)"password", 8, (uint8_t *)"salt", 4,
            (uint8_t *)"data", 4, TEST_MEMCOST, TEST_MEMCOST, TIGERKDF_TIMECOST, TIGERKDF_PARALLELISM, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }
    if(memcmp(hash1, hash2, TIGERKDF_KEYSIZE)) {
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
