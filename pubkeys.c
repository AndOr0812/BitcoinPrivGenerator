/*
 * pubkeys.c
 *
 *  Created on: 2018-01-15
 *      Author: malego
 */

#include "pubkeys.h"
#include "sha256.h"
#include "RIPEMD160.h"



void Hash_public_key(uint8_t * p_data_out, const uint8_t * p_data_in, const int data_in_len)
{
	static uint8_t sha256_buf[SHA256_HASH_SIZE];

	sha256_hash_message(p_data_in, data_in_len, (uint32_t*)sha256_buf);
	ripemd160(sha256_buf, SHA256_HASH_SIZE, p_data_out);
}

void generate_hash160_batch(unsigned char* hash160keys_p, unsigned char* pubkeys_p)
{
	for ( size_t b = 0; b < BATCH_SIZE; b++ ) {
		//Hash and verify uncompressed key
		Hash_public_key(hash160keys_p, pubkeys_p, PUBLIC_KEY_LENGTH);
		hash160keys_p += PUBLIC_KEY_HASH160_LENGTH;

		//Convert Uncompressed pubkey -> compressed pubkey
		pubkeys_p[0] = 0x02 | (pubkeys_p[64] & 0x01);

		//Hash and verify compressed key
		Hash_public_key(hash160keys_p, pubkeys_p, PUBLIC_COMPRESSED_KEY_LENGTH);
		hash160keys_p += PUBLIC_KEY_HASH160_LENGTH;

		pubkeys_p += PUBLIC_KEY_LENGTH;
	}
}
