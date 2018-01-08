
// After building secp256k1_fast_unsafe, compile benchmarks with:
//   gcc -Wall -Wno-unused-function -O2 --std=c99 -march=native -I secp256k1_fast_unsafe/src/ -I secp256k1_fast_unsafe/ ListPrivateKey.c sha256.c common.c RIPEMD160.c timer.c -lgmp -o go
//   gcc -Wall -Wno-unused-function -O2 -march=native -I secp256k1_fast_unsafe/src/ -I secp256k1_fast_unsafe/ ListPrivateKey.c common.c timer.c -lgmp -o go

//#include "RIPEMD160.h"
#include "common.h"
//#include "sha256.h"
//#include "sha256-ref.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "timer.h"

#define HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#include "secp256k1.c"
#include "ecmult_big_impl.h"
#include "secp256k1_batch_impl.h"
#include <fcntl.h> // for open
#include <unistd.h> // for close

#define BATCH_SIZE 256
#define PRIVATE_KEY_LENGTH 32
#define PUBLIC_KEY_LENGTH 65

const uint64_t max_dump_size = 128000000000;
const char privkeyhex[256] = "000000006a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a20632172F";

//SHA256_CTX sha256_ctx;
unsigned char privkeys[BATCH_SIZE*PRIVATE_KEY_LENGTH];
unsigned char pubkeys[BATCH_SIZE*PUBLIC_KEY_LENGTH];

/*
static inline void Hash_public_key(uint8_t * publicKeyHash, const uint8_t * publicKey, const int publicKeylen)
{
	static uint8_t sha256_buf[SHA256_BLOCK_SIZE];

	
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, publicKey, publicKeylen);
	sha256_final(&sha256_ctx, sha256_buf);
	ripemd160(sha256_buf, SHA256_BLOCK_SIZE, publicKeyHash);
}

static inline void Hash_public_key(uint8_t * p_data_out, const uint8_t * p_data_in, const int data_in_len)
{
	static uint8_t sha256_buf[SHA256_BLOCK_SIZE];
	
	new_sha256(sha256_buf, p_data_in);
	ripemd160(p_data_in, SHA256_BLOCK_SIZE, p_data_out);
}
*/


/*
int parse_args()
{
	    if (argc > 1) {
		printf("Starting with private key %s\n", argv[1]);
		strcpy(privkeyhex, argv[1]);
        int pos = 0;
        const char* ch = argv[1];
        while (pos < 32) {
            unsigned short sh;
            if (sscanf(ch, "%2hx", &sh)) 
			{
                privateKey_le[pos] = sh;
            } 
			else
			{
				printf("Invalid PrivateKey Provided\n");
				return 0;
            }
            ch += 2;
            pos++;
		}
    }

	if (argc > 2) {
		sprintf(filename, "%sKeys_PubC20PubU20Priv32_%s.txt", argv[2], privkeyhex);
	}else{
		sprintf(filename, "/media/malego/Data2TB/Keys_PubC20PubU20Priv32_%s.txt", privkeyhex);
	}
}
*/

int open_outfile(char* filename)
{
	printf("Opening file %s\n", filename);
	int fileDump = open(filename, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if (fileDump<=0)
	{
		printf("Error opening file\n");
		return -1;
	}
	return fileDump;
}

static inline void incr_256bit(uint64_t* p_data, int qty)
{
	//printf("Increment\n");
	p_data[0] += qty;
	if (p_data[0] == 0)
	{
		p_data[1] += qty;
		if (p_data[1] == 0)
		{
			p_data[2] += qty;
			if (p_data[2] == 0)
			{
				p_data[3] += qty;
				if (p_data[3] == 0)
				{
					printf("Msg wrap around");
					exit(0);
				}
			}
		}		
	}
	
}

// Call with a priv_key_hex first to init the function
// Subsequent call should have NULL priv_key_hex so it generate a new incremented privkey
static inline void generate_privkey(uint64_t *privkey_out, const char *privkeyhex_init, int batch_size)
{
	int i;
	
	if (privkeyhex_init)
	{
		hex2bin((uint8_t*)privkey_out, privkeyhex_init);
		for (i=1 ; i<batch_size ; i++)
		{
			memcpy(&privkey_out[i*4], &privkey_out[(i-1)*4], 32);
			incr_256bit(&privkey_out[i*4], 1);
		}
		return;
	}

	for (i=0 ; i<batch_size ; i++)
	{
		incr_256bit(&privkey_out[i*4], batch_size);
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


// Hackishly converts an uncompressed public key to a compressed public key
// The input is considered 65 bytes, the output should be considered 33 bytes
void secp256k1_pubkey_uncomp_to_comp(unsigned char *pubkey) {
    pubkey[0] = 0x02 | (pubkey[64] & 0x01);
}


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




int main(int argc, char **argv) {
    unsigned int bmul_size  = ( argc > 1 ? atoi(argv[1]) : 20 );    // ecmult_big window size in bits

    struct timespec clock_start;
    double clock_diff;

    printf("bmul  size = %u\n", bmul_size);
    printf("\n");

	//test_sha256();
	
    // Initializing secp256k1 context
    clock_start = get_clock();
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    clock_diff = get_clockdiff_s(clock_start);
    printf("main context = %12.8f\n", clock_diff);


    // Initializing secp256k1_ecmult_big context
    clock_start = get_clock();
    secp256k1_ecmult_big_context* bmul = secp256k1_ecmult_big_create(ctx, bmul_size);
    clock_diff = get_clockdiff_s(clock_start);
    printf("bmul context = %12.8f\n", clock_diff);
    printf("\n");


    // Initializing secp256k1_scratch for batched key calculations
    secp256k1_scratch *scr = secp256k1_scratch_create(ctx, BATCH_SIZE);



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
			hexdump("  privkey  = ", privkey,  32); printf("\n");
			hexdump("  expected = ", expected, 65); printf("\n");
			hexdump("  actual   = ", actual,   65); printf("\n");
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
				hexdump("  privkey  = ", p,  32); printf("\n");
				hexdump("  expected = ", e, 65); printf("\n");
				hexdump("  actual   = ", a,   65); printf("\n");
                return 1;
            }
        }
    }

    free(privkey); free(expected); free(actual);
    printf("Batched verification passed\n");
    printf("\n");



    ////////////////////////////////////////////////////////////////////////////////
    //                                 Benchmark                                  //
    ////////////////////////////////////////////////////////////////////////////////

	char filename[256];
	//unsigned char *publicKey_u_hash = (unsigned char*)safe_calloc(BATCH_SIZE, 20 * sizeof(unsigned char));
	//unsigned char *publicKey_c_hash = (unsigned char*)safe_calloc(BATCH_SIZE, 20 * sizeof(unsigned char));
    //unsigned char *privkeys = (unsigned char*)safe_calloc(BATCH_SIZE, 32 * sizeof(unsigned char));
    //unsigned char *pubkeys  = (unsigned char*)safe_calloc(BATCH_SIZE, 65 * sizeof(unsigned char));
	uint64_t file_dump_size = 0;
	int fileDump = 0;
	uint64_t iter = 0, previter =0, iterdiff;
    double batch_time ;
	int ret;
	
	sprintf(filename, "/media/malego/Data2TB/Keys_Priv256PubUncomp256_%s.txt", privkeyhex);
	fileDump = open_outfile(filename);

	generate_privkey((uint64_t*)privkeys, privkeyhex, BATCH_SIZE);
	
    clock_start = get_clock();
    while(file_dump_size < max_dump_size)
	{
		// Generate batch of private keys
		generate_privkey((uint64_t*)privkeys, NULL, BATCH_SIZE);

        // Generate associated public keys
        // Wrapped in if to prevent "ignoring return value" warning
        if ( secp256k1_ec_pubkey_create_serialized_batch(ctx, bmul, scr, pubkeys, privkeys, BATCH_SIZE, 0) );
		
		//Hash pubkeys
		/*
		unsigned char* pubkey_p = pubkeys;
		unsigned char* pubkeyhash_p = privkeys+8192;
		for ( size_t b = 0; b < BATCH_SIZE; b++ ) {			
			Hash_public_key(pubkeyhash_p, pubkey_p, 65);
			pubkeyhash_p += 20;

			secp256k1_pubkey_uncomp_to_comp(pubkey_p);
			Hash_public_key(pubkeyhash_p, pubkey_p, 33);
			pubkeyhash_p += 20;

			pubkey_p += 65;
		}
		*/
		
		//Save Keys to file
		/*
		ret = write(fileDump, privkeys, BATCH_SIZE*PRIVATE_KEY_LENGTH);
		if (ret != BATCH_SIZE*PRIVATE_KEY_LENGTH) exit(EXIT_FAILURE);
		file_dump_size += BATCH_SIZE*PRIVATE_KEY_LENGTH;
		*/
		ret = write(fileDump, pubkeys, BATCH_SIZE*PUBLIC_KEY_LENGTH);
		if (ret != BATCH_SIZE*PUBLIC_KEY_LENGTH) exit(EXIT_FAILURE);
		file_dump_size += BATCH_SIZE*PUBLIC_KEY_LENGTH;

		iterdiff = iter - previter;
		if (iterdiff==1048576/BATCH_SIZE){
			batch_time = get_clockdiff_s(clock_start);
			printf("Progress: Iter=%lu, Time=%4.2fs, HashRate=%.2fkKeys/s\n", iter, batch_time, iterdiff*BATCH_SIZE/batch_time/1000.0);
			/*for (int i =0 ; i<32;i++){
			hexdump("Private key:", &privkeys[i*32], 32);
			hexdump("Public key:", &pubkeys[i*65], 65);
			}*/
			printf("\n");
			clock_start = get_clock();
			previter = iter;
		}
		iter++;
    }

	close(fileDump);
    return 0;
}