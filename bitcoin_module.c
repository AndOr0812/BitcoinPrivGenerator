/*
 * secp256k1_iface.c
 *
 *  Created on: 2018-01-14
 *      Author: malego
 */


#define HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#include "secp256k1.c"
#include "ecmult_big_impl.h"
#include "secp256k1_batch_impl.h"

#include "bitcoin_module.h"
#include "timer.h"
#include "common.h"
#include "pthread.h"
#include "sha256.h"
#include "RIPEMD160.h"

#define BMUL_SIZE 22

void rand_privkey(unsigned char *privkey);
void *safe_calloc(size_t num, size_t size);
int secp256k1_selfcheck(secp256k1_context* ctx, secp256k1_ecmult_big_context* bmul, secp256k1_scratch *scr);
void secp256k1_init(secp256k1_context** ctx, secp256k1_ecmult_big_context** bmul, secp256k1_scratch **scr);
int full_stack_check(secp256k1_context* ctx);


const unsigned char baseline_privkey[32] = {
    // generated using srand(31415926), first 256 calls of rand() & 0xFF
    0xb9, 0x43, 0x14, 0xa3, 0x7d, 0x33, 0x46, 0x16, 0xd8, 0x0d, 0x62, 0x1b, 0x11, 0xa5, 0x9f, 0xdd,
    0x13, 0x56, 0xf6, 0xec, 0xbb, 0x9e, 0xb1, 0x9e, 0xfd, 0xe6, 0xe0, 0x55, 0x43, 0xb4, 0x1f, 0x30
};

const unsigned char baseline_expected[65] = {
    0x04, 0xfa, 0xf4, 0x5a, 0x13, 0x1f, 0xe3, 0x16, 0xe7, 0x59, 0x78, 0x17, 0xf5, 0x32, 0x14, 0x0d,
    0x75, 0xbb, 0xc2, 0xb7, 0xdc, 0xd6, 0x18, 0x35, 0xea, 0xbc, 0x29, 0xfa, 0x5d, 0x7f, 0x80, 0x25,
    0x51, 0xe5, 0xae, 0x5b, 0x10, 0xcf, 0xc9, 0x97, 0x0c, 0x0d, 0xca, 0xa1, 0xab, 0x7d, 0xc1, 0xb3,
    0x40, 0xbc, 0x5b, 0x3d, 0xf6, 0x87, 0xa5, 0xbc, 0xe7, 0x26, 0x67, 0xfd, 0x6c, 0xe6, 0xc3, 0x66, 0x29
};

pthread_mutex_t generate_pubkeysMutex = PTHREAD_MUTEX_INITIALIZER;

void generate_pubkeys(unsigned char*privkeys, unsigned char*pubkeys, int thread_id)
{
	static secp256k1_context *ctx[THREAD_QTY];
	static secp256k1_ecmult_big_context *bmul;
	static secp256k1_scratch *scr[THREAD_QTY];
	int ret;

	if (privkeys == NULL || pubkeys == NULL)
	{
		ret = pthread_mutex_lock(&generate_pubkeysMutex);
		if (ret) { /* an error has occurred */
		    perror("pthread_mutex_lock");
		    pthread_exit(NULL);
		}

		secp256k1_init(&ctx[thread_id], &bmul, &scr[thread_id]);

		secp256k1_selfcheck(ctx[thread_id], bmul, scr[thread_id]);

		full_stack_check(ctx[thread_id]);

		ret = pthread_mutex_unlock(&generate_pubkeysMutex);
		if (ret) { /* an error has occurred */
		    perror("pthread_mutex_unlock");
		    pthread_exit(NULL);
		}

	}
	else
	{
		int ret = secp256k1_ec_pubkey_create_serialized_batch(ctx[thread_id], bmul, scr[thread_id], pubkeys, privkeys, BATCH_SIZE, 0);
		if (ret == 0)
		{
			printf("generate_pubkeys : Returned 0.\n");
			exit(EXIT_FAILURE);
		}
	}
}

void rand_privkey(unsigned char *privkey) {
    // Not cryptographically secure, but good enough for quick verification tests
    for ( size_t pos = 0; pos < 32; pos++ ) {
        privkey[pos] = rand() & 0xFF;
    }
}

void *safe_calloc(size_t num, size_t size) {
    void *rtn = calloc(num, size);
    if ( !rtn ) {
        printf("calloc failed to allocate %zu items of size %zu\n", num, size);
        exit(EXIT_FAILURE);
    }
    return rtn;
}

int full_stack_check(secp256k1_context* ctx)
{
	const char * privkey = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
	const char * pubkey_u = "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6";
	const char * pubkey_c = "0250863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B235";
	const char * pubkey_u_hash256 = "600FFE422B4E00731A59557A5CCA46CC183944191006324A447BDB2D98D4B408";
	const char * pubkey_c_hash256 = "";
	const char * pubkey_u_hash160 = "010966776006953D5567439E5E39F86A0D273BEE";
	const char * pubkey_c_hash160 = "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31";

	unsigned char * privkey_bin[PRIVATE_KEY_LENGTH] 		;
	unsigned char * pubkey_u_bin[PUBLIC_KEY_LENGTH] 		;
	unsigned char * pubkey_c_bin [PUBLIC_COMPRESSED_KEY_LENGTH]		;
	unsigned char * pubkey_u_hash256_bin[SHA256_HASH_SIZE];
	unsigned char * pubkey_c_hash256_bin[SHA256_HASH_SIZE];
	unsigned char * pubkey_u_hash160_bin[PUBLIC_KEY_HASH160_LENGTH];
	unsigned char * pubkey_c_hash160_bin[PUBLIC_KEY_HASH160_LENGTH];
    unsigned char *actual   = (unsigned char*)safe_calloc(1, 65 * sizeof(unsigned char));

	hex2bin(privkey_bin, privkey);
	hex2bin(pubkey_u_bin, pubkey_u);
	hex2bin(pubkey_c_bin, pubkey_c);
	hex2bin(pubkey_u_hash256_bin, pubkey_u_hash256);
	hex2bin(pubkey_c_hash256_bin, pubkey_c_hash256);
	hex2bin(pubkey_u_hash160_bin, pubkey_u_hash160);
	hex2bin(pubkey_c_hash160_bin, pubkey_c_hash160);

	if(secp256k1_ec_pubkey_create_serialized(ctx, NULL, actual, (const unsigned char *)privkey_bin, 0));
	if (memcmp(actual, pubkey_u_bin, PUBLIC_KEY_LENGTH) !=0)
	{
		printf("BitcoinCheck: Privkey -> Pubkey = FAIL\n");
		hexdump_bytes_hn("Actual  :", actual, PUBLIC_KEY_LENGTH);printf("\n");
		hexdump_bytes_hn("Expected:", (unsigned char*)pubkey_u_bin, PUBLIC_KEY_LENGTH);
		exit(EXIT_FAILURE);
	}
	printf("BitcoinCheck: Privkey -> Pubkey = OK\n");

	sha256_hash_message((uint8_t*)pubkey_u_bin, PUBLIC_KEY_LENGTH, (uint32_t*)actual);
	if (memcmp(actual, pubkey_u_hash256_bin, SHA256_HASH_SIZE) !=0)
	{
		printf("BitcoinCheck: Privkey -> Pubkey -> SHA256 = FAIL\n");
		hexdump_bytes_hn("Actual  :", actual, SHA256_HASH_SIZE);printf("\n");
		hexdump_bytes_hn("Expected:", (unsigned char*)pubkey_u_hash256_bin, SHA256_HASH_SIZE);
		exit(EXIT_FAILURE);
	}
	printf("BitcoinCheck: Privkey -> Privkey -> SHA256 = OK\n");

	ripemd160(pubkey_u_hash256_bin, SHA256_HASH_SIZE, actual);
	if (memcmp(actual, pubkey_u_hash160_bin, PUBLIC_KEY_HASH160_LENGTH) !=0)
	{
		printf("BitcoinCheck: Privkey -> Pubkey -> SHA256 -> RIPEMD160 = FAIL\n");
		hexdump_bytes_hn("Actual  :", actual, PUBLIC_KEY_HASH160_LENGTH);
		hexdump_bytes_hn("Expected:", (unsigned char*)pubkey_u_hash160_bin, PUBLIC_KEY_HASH160_LENGTH);
		exit(EXIT_FAILURE);
	}
	printf("BitcoinCheck: Privkey -> Privkey -> SHA256 -> RIPEMD160 = OK\n");


	return 0;

}



void secp256k1_init(secp256k1_context** ctx, secp256k1_ecmult_big_context** bmul, secp256k1_scratch **scr)
{
	struct timespec clock_start ;
	double clock_diff;

    printf("bmul  size = %u\n", BMUL_SIZE);

    if (*ctx == NULL)
    {
    	printf("Initializing secp256k1 context\n");
		clock_start = get_clock();
		*ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
		clock_diff = get_clockdiff_s(clock_start);
		printf("main context = %12.8f\n", clock_diff);
    }
    if (*bmul == NULL)
    {
		printf("Initializing secp256k1_ecmult_big context\n");
		clock_start = get_clock();
		*bmul = secp256k1_ecmult_big_create(*ctx, BMUL_SIZE);
		clock_diff = get_clockdiff_s(clock_start);
		printf("bmul context = %12.8f\n", clock_diff);
		printf("\n");
    }

    if (*scr == NULL)
    {
		// Initializing secp256k1_scratch for batched key calculations
		*scr = secp256k1_scratch_create(*ctx, BATCH_SIZE);
    }
}

int secp256k1_selfcheck(secp256k1_context* ctx, secp256k1_ecmult_big_context* bmul, secp256k1_scratch *scr)
{
    ////////////////////////////////////////////////////////////////////////////////
    //                                Verification                                //
    ////////////////////////////////////////////////////////////////////////////////

    size_t test_count = 1024;
    size_t expected_count;
    size_t actual_count;

    // Verify serial pubkey generation
    unsigned char *privkey  = (unsigned char*)safe_calloc(1, 32 * sizeof(unsigned char));
    unsigned char *expected = (unsigned char*)safe_calloc(1, 65 * sizeof(unsigned char));
    unsigned char *actual   = (unsigned char*)safe_calloc(1, 65 * sizeof(unsigned char));


    // Quick baseline test to make sure we can trust our "expected" results
    memcpy(privkey,  baseline_privkey,  32);
    memcpy(expected, baseline_expected, 65);

    expected_count = 1;
    actual_count   = secp256k1_ec_pubkey_create_serialized(ctx, NULL, actual, privkey, 0);

    if ( actual_count != expected_count ) {
        printf("Baseline verification warning\n");
        printf("  expected count = %zu\n", expected_count);
        printf("  actual   count = %zu\n", actual_count);
    }

    if ( memcmp(expected, actual, 65) != 0 ) {
        printf("Baseline verification failed\n");
        return 1;
    }
    printf("Baseline verification passed\n");


    // Verify that using the faster bmul context returns correct results
    for ( size_t iter = 0; iter < test_count; iter++ ) {
        rand_privkey(privkey);

        // Known working result
        expected_count = secp256k1_ec_pubkey_create_serialized(ctx, NULL, expected, privkey, 0);

        // Method being tested
        actual_count   = secp256k1_ec_pubkey_create_serialized(ctx, bmul, actual,   privkey, 0);


        if ( expected_count != actual_count ) {
            printf("Serial verification warning on iteration %zu\n", iter);
            printf("  expected count = %zu\n", expected_count);
            printf("  actual   count = %zu\n", actual_count);
        }

        if ( memcmp(expected, actual, 65) != 0 ) {
            printf("Serial verification failed on iteration %zu\n", iter);
			hexdump_bytes_hn("  privkey  = ", privkey,  32); printf("\n");
			hexdump_bytes_hn("  expected = ", expected, 65); printf("\n");
			hexdump_bytes_hn("  actual   = ", actual,   65); printf("\n");
            return 1;
        }
    }

    free(privkey); free(expected); free(actual);
    printf("Serial verification passed\n");


    // Verify batched pubkey generation
    // If we made it this far, we can trust ecmult_big results, so we'll
    //   use it to make this part of the verification go a little faster
    privkey  = (unsigned char*)safe_calloc(BATCH_SIZE, 32 * sizeof(unsigned char));
    expected = (unsigned char*)safe_calloc(BATCH_SIZE, 65 * sizeof(unsigned char));
    actual   = (unsigned char*)safe_calloc(BATCH_SIZE, 65 * sizeof(unsigned char));

    for ( size_t batch = 0; batch < test_count / BATCH_SIZE; batch++ ) {
        expected_count = 0;

        for ( size_t i = 0; i < BATCH_SIZE; i++ ) {
            rand_privkey(&privkey[32 * i]);
            expected_count += secp256k1_ec_pubkey_create_serialized(ctx, bmul, &expected[65 * i], &privkey[32 * i], 0);
        }

        actual_count = secp256k1_ec_pubkey_create_serialized_batch(ctx, bmul, scr, actual, privkey, BATCH_SIZE, 0);


        if ( expected_count != actual_count ) {
            printf("Batch verification warning on batch %zu\n", batch);
            printf("  expected count = %zu\n", expected_count);
            printf("  actual   count = %zu\n", actual_count);
        }

        for ( size_t i = 0; i < BATCH_SIZE; i++ ) {
            unsigned char *p = &( privkey[32 * i]);
            unsigned char *e = &(expected[65 * i]);
            unsigned char *a = &(  actual[65 * i]);

            if ( memcmp(e, a, 65) != 0 ) {
                printf("Batch verification failed on batch %zu item %zu\n", batch, i);
				hexdump_bytes_hn("  privkey  = ", p,  32); printf("\n");
				hexdump_bytes_hn("  expected = ", e, 65); printf("\n");
				hexdump_bytes_hn("  actual   = ", a,   65); printf("\n");
                return 1;
            }
        }
    }

    free(privkey); free(expected); free(actual);
    printf("Batched verification passed\n");
    printf("\n");
    return 0;
}
