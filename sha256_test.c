/*********************************************************************
* Filename:   sha256.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding SHA1
	          implementation. These tests do not encompass the full
	          range of available test vectors, however, if the tests
	          pass it is very, very likely that the code is correct
	          and was compiled properly. This code also serves as
	          example usage of the functions.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include "sha256.h"

/*********************** FUNCTION DEFINITIONS ***********************/
void test_sha256()
{
	static uint8_t sha256_buf[2][SHA256_BLOCK_SIZE];
	char *value_hex =        "000050006a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a20632172e000050006a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a20632172e00";
	char *value_hex_suffix = "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000208";
	uint8_t value_bin[128] ;
	hex2bin(value_bin, value_hex);
	hex2bin(&value_bin[65], value_hex_suffix);
	int i;
	
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, value_bin, 65);
	sha256_final(&sha256_ctx, sha256_buf[0]);
	hexdump("Old: ", sha256_buf[0], 32);

	static const uint32_t __sha256_init[] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};
	__builtin_memcpy(sha256_buf[1], __sha256_init, 32);
	__sha256_osol(value_bin, (uint32_t*)sha256_buf[1]);
	hexdump("New: ", sha256_buf[1], 32);
	__sha256_osol(&value_bin[64], (uint32_t*)sha256_buf[1]);	
	hexdump("New: ", sha256_buf[1], 32);
	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 8; ++i) {
		((uint32_t*)sha256_buf[1])[i] = __bswap_32(((uint32_t*)sha256_buf[1])[i]);
	}
/*    for ( size_t pos = 0; pos < 32; pos+=4 ) {
		cpu_to_be32s(&sha256_buf[1][pos]);
	}
	*/
	hexdump("New: ", sha256_buf[1], 32);
}

int main()
{
	SHA256_CTX ctx;
	WORD m[16];
	int i;

	memset(m, 0, 64);
	
	for(m[0]=0xFFFFFFFF ; m[0]!=0 ; m[0]--)
	{
		sha256_init_inv(&ctx, m);
		sha256_transform_inv(&ctx);
		sha256_final_inv(&ctx);
	}
	return(0);
}
