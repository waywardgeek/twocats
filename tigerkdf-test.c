// I, Bill Cox, initially copied this file from Catena's src/catena_test_vectors.c in
// 2014, and modified it to call TigerKDF.  It was written by the Catena team and slightly
// changed by me.  It therefore falls under Catena's MIT license.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tigerkdf.h"
#include "tigerkdf-impl.h"

/*******************************************************************/

void test_output(uint8_t hashlen,
                 uint8_t *pwd,   uint32_t pwdlen,
                 uint8_t *salt,  uint8_t saltlen,
                 uint8_t *data,  uint32_t datalen,
                 uint32_t memlen, uint32_t multipliesPerKB,
                 uint8_t garlic, uint32_t blocklen,
                 uint32_t subBlocklen,
                 uint32_t parallelism, uint32_t repetitions)
{
    uint8_t hash[hashlen];

    printHex("Password: ",pwd, pwdlen);
    printHex("Salt: ",salt, saltlen);
    printHex("Associated data:", data, datalen);
    printf("garlic:%u memorySize:%u multipliesPerKB:%u repetitions:%u\n",
        garlic, memlen, multipliesPerKB, repetitions);
    printf("numThreads:%u blockSize:%u subBlockSize:%u\n",
        parallelism, blocklen, subBlocklen);

    if(!TigerKDF_HashPassword(hash, hashlen, pwd, pwdlen, salt, saltlen, memlen,
            multipliesPerKB, garlic, data, datalen, blocklen, subBlocklen, parallelism,
            repetitions, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }

    printHex("\nOutput: ", hash, hashlen);
    puts("\n\n");
}


/*******************************************************************/

void simpletest(char *password, char *salt, char *data, uint32_t memlen)
{
    test_output(64, (uint8_t *)password, strlen(password), (uint8_t *)salt, strlen(salt),
        (uint8_t *)data, strlen(data), memlen, 200, 0, TIGERKDF_BLOCKSIZE,
        TIGERKDF_SUBBLOCKSIZE, 1, 1);
}

/*******************************************************************/

void PHC_test(void)
{
    int i;
    uint8_t j = 0;

    printf("****************************************** Test passwords\n");
    for(i=0; i < 256; i++) {
        test_output(32, (uint8_t *) &i, 1, &j, 1, NULL, 0, 1*1024, 200, 0,
            TIGERKDF_BLOCKSIZE, TIGERKDF_SUBBLOCKSIZE, 1, 1);
    }
    printf("****************************************** Test salt\n");
    for(i=0; i < 256; i++) {
        test_output(32, &j, 1, (uint8_t *) &i, 1, NULL, 0, 1*1024, 200, 0,
            TIGERKDF_BLOCKSIZE, TIGERKDF_SUBBLOCKSIZE, 1, 1);
    }
    printf("****************************************** Test data\n");
    for(i=0; i < 256; i++) {
        test_output(32, &j, 1, &j, 1, (uint8_t *) &i, 1, 10*1024, 200, 0,
            TIGERKDF_BLOCKSIZE, TIGERKDF_SUBBLOCKSIZE, 1, 1);
    }
    printf("****************************************** Test garlic\n");
    for(i=0; i < 6; i++) {
        test_output(32, &j, 1, &j, 1, NULL, 0, 1*1024, 200, i, TIGERKDF_BLOCKSIZE,
            TIGERKDF_SUBBLOCKSIZE, 1, 1);
    }
    printf("****************************************** Test parallelism\n");
    for(i=1; i < 10; i++) {
        test_output(32, &j, 1, &j, 1, NULL, 0, 1*1024, 200, 0, TIGERKDF_BLOCKSIZE,
            TIGERKDF_SUBBLOCKSIZE, i, 1);
    }
    printf("****************************************** Test repetitions\n");
    for(i=1; i < 10; i++) {
        test_output(32, &j, 1, &j, 1, NULL, 0, 1*1024, 200, 0, TIGERKDF_BLOCKSIZE,
            TIGERKDF_SUBBLOCKSIZE, 1, i);
    }
    printf("****************************************** Test blocklen\n");
    for(i=32; i < 1024; i += 32) {
        test_output(12, &j, 1, &j, 1, NULL, 0, 1*1024, i, 0, i, 0, 1, 1);
    }
    printf("****************************************** Test memlen\n");
    for(i=1; i < 16; i += 4) {
        test_output(32, &j, 1, &j, 1, NULL, 0, i*1024, 200, 0, TIGERKDF_BLOCKSIZE,
            TIGERKDF_SUBBLOCKSIZE, 1, 1);
    }
}

void verifyGarlic(void) {
    uint32_t garlic;
    uint8_t hash1[32], hash2[32];

    if(!TigerKDF_HashPassword(hash1, 32, (uint8_t *)"password", 8,
            (uint8_t *)"salt", 4, 1*1024, 200, 0, NULL, 0, TIGERKDF_BLOCKSIZE,
            TIGERKDF_SUBBLOCKSIZE, 1, 1, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }
    for(garlic = 1; garlic < 10; garlic++) {
        if(!TigerKDF_HashPassword(hash2, 32, (uint8_t *)"password", 8,
                (uint8_t *)"salt", 4, 1*1024, 200, garlic, NULL, 0, TIGERKDF_BLOCKSIZE,
                TIGERKDF_SUBBLOCKSIZE, 1, 1, false)) {
            fprintf(stderr, "Password hashing failed!\n");
            exit(1);
        }
        if(!TigerKDF_UpdatePasswordHash(hash1, 32, 1*1024, 200, garlic, garlic,
            TIGERKDF_BLOCKSIZE, TIGERKDF_SUBBLOCKSIZE, 1, 1)) {
            fprintf(stderr, "Password hashing failed!\n");
            exit(1);
        }
        if(memcmp(hash1, hash2, 32)) {
            fprintf(stderr, "Password update got wrong answer!\n");
            exit(1);
        }
    }
}

void verifyClientServer(void) {
    uint8_t hash1[32];
    if(!TigerKDF_ClientHashPassword(hash1, 32, (uint8_t *)"password", 8, (uint8_t *)"salt",
            4, 1024*1024, 200, 0, (uint8_t *)"data", 4, TIGERKDF_BLOCKSIZE,
            TIGERKDF_SUBBLOCKSIZE, 2, 2, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }
    TigerKDF_ServerHashPassword(hash1, 32);
    uint8_t hash2[32];
    if(!TigerKDF_HashPassword(hash2, 32, (uint8_t *)"password", 8, (uint8_t *)"salt", 4,
            1024*1024, 200, 0, (uint8_t *)"data", 4, TIGERKDF_BLOCKSIZE,
            TIGERKDF_SUBBLOCKSIZE, 2, 2, false)) {
        fprintf(stderr, "Password hashing failed!\n");
        exit(1);
    }
    if(memcmp(hash1, hash2, 32)) {
        fprintf(stderr, "Password client/server got wrong answer!\n");
        exit(1);
    }
}

/*******************************************************************/

int main()
{
    printf("****************************************** Basic tests\n");

    verifyClientServer();
    verifyGarlic();

    simpletest("password", "salt", "", 1*1024);
    simpletest("password", "salt", "", 1024*1024);
    simpletest("password", "salt", "data", 1024*1024);
    simpletest("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt","", 1*1024);

    PHC_test();

    printf("****************************************** Misc tests\n");
    test_output(128, (uint8_t *)"password", strlen("password"), (uint8_t *)"salt",
        strlen("salt"), NULL, 0, 1024*1024, 200, 0, TIGERKDF_BLOCKSIZE,
        TIGERKDF_SUBBLOCKSIZE, 2, 1);
    test_output(64, (uint8_t *)"password", strlen("password"), (uint8_t *)"salt",
        strlen("salt"), NULL, 0, 10*1024, 200, 0, 1024, 32, 1, TIGERKDF_SUBBLOCKSIZE);
    test_output(64, (uint8_t *)"password", strlen("password"), (uint8_t *)"salt",
        strlen("salt"), NULL, 0, 10*1024, 200, 4, 128, 0, 1, 1);

    return 0;
}
