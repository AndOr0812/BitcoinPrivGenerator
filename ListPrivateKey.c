
// After building secp256k1_fast_unsafe, compile benchmarks with:
//   gcc -Wall -Wno-unused-function -O2 --std=c99 -march=native -I secp256k1_fast_unsafe/src/ -I secp256k1_fast_unsafe/ ListPrivateKey.c sha256.c common.c RIPEMD160.c timer.c -lgmp -o go

/*
gcc -Wno-unused-function -O2 -march=native -I ../lib/secp256k1_fast_unsafe/ ListPrivateKey.c common.c timer.c RIPEMD160.c ../lib/sha256_asm/sha256-x8664.S -lgmp -o go
gcc -Wno-unused-function -O2 -march=native -I ../lib/secp256k1_fast_unsafe/ ListPrivateKey.c common.c timer.c RIPEMD160.c ../lib/sha256_asm/sha256-x8664.S -lgmp -lart -o goArt
*/

#include "RIPEMD160.h"
#include "common.h"
#include "art.h"
//#include "sha256.h"
//#include "sha256-ref.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "timer.h"

#define HAVE_CONFIG_H
#include "src/libsecp256k1-config.h"
#include "src/secp256k1.c"
#include "src/ecmult_big_impl.h"
#include "src/secp256k1_batch_impl.h"
#include <fcntl.h> // for open
#include <unistd.h> // for close

#define BATCH_SIZE 256
#define PRIVATE_KEY_LENGTH 32
#define PUBLIC_KEY_LENGTH 65
#define PUBLIC_COMPRESSED_KEY_LENGTH 33
#define PUBLIC_KEY_HASH160_LENGTH 20

#define SHA256_HASH_SIZE 32
#define BLOCK_LEN 64  // In bytes
#define STATE_LEN 8  // In words

static int sha256_self_check(void);
void sha256_hash_message(const uint8_t message[], size_t len, uint32_t hash[static STATE_LEN]);
void *safe_calloc(size_t num, size_t size);

// Link this program with an external C or x86 compression function
extern void sha256_compress(uint32_t state[static STATE_LEN], const uint8_t block[static BLOCK_LEN]);
extern int art_best_depth;





const uint64_t max_dump_size = 40000000000;
const char privkeyhex[256] = "000000006a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321731";
const unsigned int bmul_size  = 20;    // ecmult_big window size in bits
char UTXO_filename[] = "/home/malego/Projects/Bitcoin/UTXO.txt";

//SHA256_CTX sha256_ctx;
unsigned char privkeys[BATCH_SIZE*PRIVATE_KEY_LENGTH];
unsigned char pubkeys[BATCH_SIZE*PUBLIC_KEY_LENGTH];
art_tree t;
float balances[2000000];
int show_min_match = 7;

/*
static inline void Hash_public_key(uint8_t * publicKeyHash, const uint8_t * publicKey, const int publicKeylen)
{
	static uint8_t sha256_buf[SHA256_BLOCK_SIZE];

	
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, publicKey, publicKeylen);
	sha256_final(&sha256_ctx, sha256_buf);
	ripemd160(sha256_buf, SHA256_BLOCK_SIZE, publicKeyHash);
}
*/
static inline void Hash_public_key(uint8_t * p_data_out, const uint8_t * p_data_in, const int data_in_len)
{
	static uint8_t sha256_buf[SHA256_HASH_SIZE];
	
	sha256_hash_message(p_data_in, data_in_len, (uint32_t*)sha256_buf);
	ripemd160(sha256_buf, SHA256_HASH_SIZE, p_data_out);
}



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
/* Test vectors and checker */

static int sha256_self_check(void) {
	struct TestCase {
		uint32_t answer[STATE_LEN];
		const char *message;
	};
	
	static const struct TestCase cases[] = {
		#define TESTCASE(a,b,c,d,e,f,g,h,msg) {{UINT32_C(a),UINT32_C(b),UINT32_C(c),UINT32_C(d),UINT32_C(e),UINT32_C(f),UINT32_C(g),UINT32_C(h)}, msg}
		TESTCASE(0xE3B0C442,0x98FC1C14,0x9AFBF4C8,0x996FB924,0x27AE41E4,0x649B934C,0xA495991B,0x7852B855, ""),
		TESTCASE(0xCA978112,0xCA1BBDCA,0xFAC231B3,0x9A23DC4D,0xA786EFF8,0x147C4E72,0xB9807785,0xAFEE48BB, "a"),
		TESTCASE(0xBA7816BF,0x8F01CFEA,0x414140DE,0x5DAE2223,0xB00361A3,0x96177A9C,0xB410FF61,0xF20015AD, "abc"),
		TESTCASE(0xF7846F55,0xCF23E14E,0xEBEAB5B4,0xE1550CAD,0x5B509E33,0x48FBC4EF,0xA3A1413D,0x393CB650, "message digest"),
		TESTCASE(0x71C480DF,0x93D6AE2F,0x1EFAD144,0x7C66C952,0x5E316218,0xCF51FC8D,0x9ED832F2,0xDAF18B73, "abcdefghijklmnopqrstuvwxyz"),
		TESTCASE(0x248D6A61,0xD20638B8,0xE5C02693,0x0C3E6039,0xA33CE459,0x64FF2167,0xF6ECEDD4,0x19DB06C1, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
		#undef TESTCASE
	};
	
	size_t numCases = sizeof(cases) / sizeof(cases[0]);
	for (size_t i = 0; i < numCases; i++) {
		const struct TestCase *tc = &cases[i];
		size_t len = strlen(tc->message);
		/*uint8_t *msg = calloc(len, sizeof(uint8_t));
		if (msg == NULL) {
			perror("calloc");
			exit(1);
		}
		//for (size_t j = 0; j < len; j++)
		//	msg[j] = (uint8_t)tc->message[j];
		*/
		uint32_t hash[STATE_LEN];
		sha256_hash_message((uint8_t*)tc->message, len, hash);
		for (i=0 ; i<8 ; i++)
		{
			hash[i]  = htobe32(hash[i]);
		}

		if (memcmp(hash, tc->answer, sizeof(tc->answer)) != 0)
			return 0;
		//free(msg);
	}
	return 1;
}

void sha256_hash_message(const uint8_t message[], size_t len, uint32_t hash[static STATE_LEN]) {
	int i;
	hash[0] = UINT32_C(0x6A09E667);
	hash[1] = UINT32_C(0xBB67AE85);
	hash[2] = UINT32_C(0x3C6EF372);
	hash[3] = UINT32_C(0xA54FF53A);
	hash[4] = UINT32_C(0x510E527F);
	hash[5] = UINT32_C(0x9B05688C);
	hash[6] = UINT32_C(0x1F83D9AB);
	hash[7] = UINT32_C(0x5BE0CD19);
	
	#define LENGTH_SIZE 8  // In bytes
	
	size_t off;
	for (off = 0; len - off >= BLOCK_LEN; off += BLOCK_LEN)
		sha256_compress(hash, &message[off]);
	
	uint8_t block[BLOCK_LEN] = {0};
	size_t rem = len - off;
	memcpy(block, &message[off], rem);
	
	block[rem] = 0x80;
	rem++;
	if (BLOCK_LEN - rem < LENGTH_SIZE) {
		sha256_compress(hash, block);
		memset(block, 0, sizeof(block));
	}
	
	block[BLOCK_LEN - 1] = (uint8_t)((len & 0x1FU) << 3);
	len >>= 5;
	for (i = 1; i < LENGTH_SIZE; i++, len >>= 8)
		block[BLOCK_LEN - 1 - i] = (uint8_t)(len & 0xFFU);
	sha256_compress(hash, block);
	for (i=0 ; i<8 ; i++)
	{
		hash[i]  = htobe32(hash[i]);
	}
}

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

 // Call with a priv_key_hex first to init the function
// Subsequent call should have NULL priv_key_hex so it generate a new incremented privkey
static inline void generate_privkey_from_file(uint64_t *privkey_out, int command, int batch_size)
{
	static FILE * fin;
    char * line = NULL;
    size_t buflen ;
    ssize_t read;

	switch(command){
		case 0:
			fin = fopen("/home/malego/Downloads/crackstation.txt", "r");
			if (fin == NULL){
				printf("Error opening file\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 1:
			for (int i=0 ; i<batch_size ; i++)
			{
				read = getline(&line, &buflen, fin);
				if (read == -1){
					printf("End of file");
					exit(EXIT_FAILURE);
				}
				//printf("Retrieved read %ld length %zu : %s", read, buflen, line);
				sha256_hash_message(line, read-1, (unsigned int *)&privkey_out[i*4]);
			}
			free(line);
			break;
		default:
			fclose(fin);
			if (line)
				free(line);
	}
}

int bitcoin_check(secp256k1_context* ctx)
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

	hex2bin(privkey_bin, privkey);
	hex2bin(pubkey_u_bin, pubkey_u);
	hex2bin(pubkey_c_bin, pubkey_c);
	hex2bin(pubkey_u_hash256_bin, pubkey_u_hash256);
	hex2bin(pubkey_c_hash256_bin, pubkey_c_hash256);
	hex2bin(pubkey_u_hash160_bin, pubkey_u_hash160);
	hex2bin(pubkey_c_hash160_bin, pubkey_c_hash160);

    unsigned char *actual   = (unsigned char*)safe_calloc(1, PUBLIC_KEY_LENGTH * sizeof(unsigned char));
	
	if(secp256k1_ec_pubkey_create_serialized(ctx, NULL, actual, (const unsigned char *)privkey_bin, 0));
	if (memcmp(actual, pubkey_u_bin, PUBLIC_KEY_LENGTH) !=0)
	{
		printf("BitcoinCheck: Privkey -> Pubkey = FAIL\n");
		hexdump("Actual  :", actual, PUBLIC_KEY_LENGTH);printf("\n");
		hexdump("Expected:", (const unsigned char*)pubkey_u_bin, PUBLIC_KEY_LENGTH);printf("\n");
		exit(EXIT_FAILURE);
	}
	printf("BitcoinCheck: Privkey -> Pubkey = OK\n");
	
	sha256_hash_message((uint8_t*)pubkey_u_bin, PUBLIC_KEY_LENGTH, (uint32_t*)actual);
	if (memcmp(actual, pubkey_u_hash256_bin, SHA256_HASH_SIZE) !=0)
	{
		printf("BitcoinCheck: Privkey -> Pubkey -> SHA256 = FAIL\n");
		hexdump("Actual  :", actual, SHA256_HASH_SIZE);printf("\n");
		hexdump("Expected:", (const unsigned char*)pubkey_u_hash256_bin, SHA256_HASH_SIZE);printf("\n");
		exit(EXIT_FAILURE);
	}
	printf("BitcoinCheck: Privkey -> Privkey -> SHA256 = OK\n");
	
	ripemd160(pubkey_u_hash256_bin, SHA256_HASH_SIZE, actual);
	if (memcmp(actual, pubkey_u_hash160_bin, PUBLIC_KEY_HASH160_LENGTH) !=0)
	{
		printf("BitcoinCheck: Privkey -> Pubkey -> SHA256 -> RIPEMD160 = FAIL\n");
		hexdump("Actual  :", actual, PUBLIC_KEY_HASH160_LENGTH);printf("\n");
		hexdump("Expected:", (const unsigned char*)pubkey_u_hash160_bin, PUBLIC_KEY_HASH160_LENGTH);printf("\n");
		exit(EXIT_FAILURE);
	}
	printf("BitcoinCheck: Privkey -> Privkey -> SHA256 -> RIPEMD160 = OK\n");
	
	
	
	
	
	
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


void load_lookup(int src_as_hex, int dest_as_hex, int print_progress)
{
	
	int len, duplicate_qty, zero_qty = 0;
    char linebuf[512];
    unsigned char key_buf[20];
    int res = art_tree_init(&t);
	char *pubkey_hex_p, *balance_str_p;
	float*balance_p = balances;
	void* ret_p = NULL;
	int src_key_length, dest_key_length;
	
    FILE *f = fopen(UTXO_filename, "r");

    uintptr_t line = 1;
    while (fgets(linebuf, sizeof linebuf, f)) {
		src_key_length = (src_as_hex) ? 40 : 20;
		dest_key_length = (dest_as_hex) ? 40 : 20;
		if (src_as_hex){
			// initialize the string tokenizer and receive pointer to first token
			pubkey_hex_p = strtok(linebuf, " ,.\n");
			balance_str_p = strtok(NULL, " ,.\n");
			*balance_p = atof(balance_str_p);
			if (dest_as_hex) 
				memcpy(key_buf, pubkey_hex_p, src_key_length);	
			else 
				hex2bin(key_buf, pubkey_hex_p);
			
		}else{
			pubkey_hex_p = malloc(32);		
			bin2hex(pubkey_hex_p, linebuf, src_key_length);
			if (dest_as_hex) 
				bin2hex(key_buf, linebuf, src_key_length);
			else 
				memcpy(key_buf, linebuf, src_key_length);
			
		}
		
		ret_p = art_insert(&t, key_buf, dest_key_length, balance_p);
        if ( ret_p != NULL ){
			duplicate_qty++;
			if (print_progress) printf("Duplicate P:%p  Key: %s Balance: %6.4f\n", ret_p, pubkey_hex_p, *balance_p);
		}
        if ( line % (1024) == 0 ){
			if (print_progress) printf("Progress Key: %s Balance: %6.4f\n", pubkey_hex_p, *balance_p);
		}
		/*
		
        if ( *balance_p > 0.0 ){
			printf("Progress P:%p  Key: %s Balance: %6.4f\n", ret_p, pubkey_hex_p, *balance_p);
		}
		*/
        if ( *balance_p == 0.0 ){
			zero_qty++;
			//printf("ZeroBalance P:%p  Key: %s Balance: %6.4f\n", ret_p, pubkey_hex_p, *balance_p);
		}
		
		if (pubkey_hex_p) free(pubkey_hex_p);
        line++;
		balance_p++;
    }
	printf("Tree got %lu elements with %d Zero-Balance, after removing %d duplicate.\n", art_size(&t), zero_qty,  duplicate_qty);


}

int verify_match(unsigned char * buf, unsigned char * privkey_p, unsigned char * pubkey_p, unsigned char * pubkey_hash_p, int best_match_len){
	
	uintptr_t val = (uintptr_t)art_search(&t, buf, 40);
	if (val){
		printf("FOUND!!!!!!!!!!!!!!!!!1\n");
		hexdump("Private key    :", privkey_p, PRIVATE_KEY_LENGTH);
		hexdump("Public key U   :", pubkey_p, PUBLIC_KEY_LENGTH);
		hexdump("Pubkey Has160 U:", pubkey_hash_p, PUBLIC_KEY_HASH160_LENGTH);
		printf("FOUND!!!!!!!!!!!!!!!!!1\n");
		exit(EXIT_SUCCESS);
	}
	if(art_best_depth >= show_min_match){
		printf("Match len=%d : ", art_best_depth);				
		hexdump("Pubkey Has160 C : ", pubkey_hash_p, PUBLIC_KEY_HASH160_LENGTH);				
		printf("\n");
		//exit(EXIT_SUCCESS);
	}
	return (art_best_depth > best_match_len) ? art_best_depth : best_match_len;
}

int main(int argc, char **argv) {
	if (argc>1)show_min_match = atoi(argv[1]);
    struct timespec clock_start;
    double clock_diff;
	
    printf("bmul  size = %u\n", bmul_size);
    printf("\n");

	// test_sha256
	if (!sha256_self_check()) {
		printf("Self-check failed\n");
		return EXIT_FAILURE;
	}
	printf("SHA256 Self-check passed\n");
	
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

	//Bitcoin test
	bitcoin_check(ctx);
	load_lookup(0);
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

	char filename_out[256];
	unsigned char *publicKeys_hash = (unsigned char*)safe_calloc(BATCH_SIZE, 2 * 20 * sizeof(unsigned char));
	//unsigned char *publicKey_c_hash = (unsigned char*)safe_calloc(BATCH_SIZE, 20 * sizeof(unsigned char));
    //unsigned char *privkeys = (unsigned char*)safe_calloc(BATCH_SIZE, 32 * sizeof(unsigned char));
    unsigned char *pubkeys_C  = (unsigned char*)safe_calloc(BATCH_SIZE, 33 * sizeof(unsigned char));
	uint64_t file_dump_size = 0;
	int fileDump = 0;
	uint64_t iter = 0, previter =0, iterdiff;
    double batch_time ;
	int ret;
	uintptr_t val;
	char buf[128];
	int best_match_length = 0;
	
	sprintf(filename_out, "/media/malego/Data2TB/PubkeyHash160_%s.bin", "crackstation");
	fileDump = open_outfile(filename_out);

	//generate_privkey((uint64_t*)privkeys, privkeyhex, BATCH_SIZE);
	printf("Opening read file\n");
	generate_privkey_from_file((uint64_t*)privkeys, 0, BATCH_SIZE);
	printf("getting 256 keys\n");
	generate_privkey_from_file((uint64_t*)privkeys, 1, BATCH_SIZE);
	printf("Crunching now\n");
    clock_start = get_clock();
    while(file_dump_size < max_dump_size)
	{
        // Generate associated public keys
        // Wrapped in if to prevent "ignoring return value" warning
        if ( secp256k1_ec_pubkey_create_serialized_batch(ctx, bmul, scr, pubkeys, privkeys, BATCH_SIZE, 0) );
		
		//Hash pubkeys
		
		unsigned char* pubkey_p = pubkeys;
		unsigned char* pubkey_c_p = pubkeys_C;
		unsigned char* pubkeyhash_p = publicKeys_hash;
		
		for ( size_t b = 0; b < BATCH_SIZE; b++ ) {			
			Hash_public_key(pubkeyhash_p, pubkey_p, PUBLIC_KEY_LENGTH);
			
			bin2hex(buf, pubkeyhash_p, 20);
			best_match_length = verify_match((unsigned char*)buf, &privkeys[b*PRIVATE_KEY_LENGTH], pubkey_c_p, pubkeyhash_p, best_match_length);
			pubkeyhash_p += PUBLIC_KEY_HASH160_LENGTH;
			memcpy(pubkey_c_p, pubkey_p, PUBLIC_COMPRESSED_KEY_LENGTH);
			pubkey_c_p[0] = 0x02 | (pubkey_p[64] & 0x01);
			Hash_public_key(pubkeyhash_p, pubkey_c_p, PUBLIC_COMPRESSED_KEY_LENGTH);

			bin2hex(buf, pubkeyhash_p, 20);
			best_match_length = verify_match((unsigned char*)buf, &privkeys[b*PRIVATE_KEY_LENGTH], pubkey_c_p, pubkeyhash_p, best_match_length);
			
			pubkeyhash_p += PUBLIC_KEY_HASH160_LENGTH;
			pubkey_c_p += PUBLIC_COMPRESSED_KEY_LENGTH;
			pubkey_p += PUBLIC_KEY_LENGTH;
		}
		
		
		//Save Keys to file
		/*
		ret = write(fileDump, privkeys, BATCH_SIZE*PRIVATE_KEY_LENGTH);
		if (ret != BATCH_SIZE*PRIVATE_KEY_LENGTH) exit(EXIT_FAILURE);
		file_dump_size += BATCH_SIZE*PRIVATE_KEY_LENGTH;
		
		int write_length = BATCH_SIZE*PUBLIC_KEY_HASH160_LENGTH*2;
		ret = write(fileDump, publicKeys_hash,write_length);
		if (ret != write_length) exit(EXIT_FAILURE);
		file_dump_size += write_length;
		*/
		iterdiff = iter - previter;
		if (iterdiff==1048576){
			batch_time = get_clockdiff_s(clock_start);
			printf("Progress: Iter=%lu, Time=%4.2fs, HashRate=%.2fkKeys/s Best_match_length=%d\n", iter, batch_time, iterdiff/batch_time/1000.0, best_match_length);
			//for (int i =0 ; i<32;i++){
			/*
				hexdump("Private key    :", privkeys, PRIVATE_KEY_LENGTH);
				hexdump("Public key U   :", pubkeys, PUBLIC_KEY_LENGTH);
				hexdump("Public key C   :", pubkeys_C, PUBLIC_COMPRESSED_KEY_LENGTH);
				hexdump("Pubkey Has160 U:", publicKeys_hash, PUBLIC_KEY_HASH160_LENGTH);
				hexdump("Pubkey Has160 C:", publicKeys_hash+20, PUBLIC_KEY_HASH160_LENGTH);
			*/
			//}
			printf("\n");
			clock_start = get_clock();
			previter = iter;
		}
		
		// Generate batch of private keys
		generate_privkey_from_file((uint64_t*)privkeys, 1, BATCH_SIZE);
		//generate_privkey((uint64_t*)privkeys, NULL, BATCH_SIZE);
		iter+=BATCH_SIZE;
    }
	printf("Best match length = %d\n.", best_match_length);
	generate_privkey_from_file((uint64_t*)privkeys, 2, BATCH_SIZE);
	free(publicKeys_hash);
	close(fileDump);
    return 0;
}