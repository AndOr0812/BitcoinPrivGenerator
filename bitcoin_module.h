/*
 * bitcoin.h
 *
 *  Created on: 2018-01-13
 *      Author: malego
 */

#ifndef BITCOIN_H_
#define BITCOIN_H_

#define PRIVATE_KEY_LENGTH 32
#define PUBLIC_KEY_LENGTH 65
#define PUBLIC_COMPRESSED_KEY_LENGTH 33
#define PUBLIC_KEY_HASH160_LENGTH 20
#define SHA256_HASH_SIZE 32
#define BATCH_SIZE 256
#define THREAD_QTY 12


void generate_pubkeys(unsigned char*privkeys, unsigned char*pubkeys,  int thread_id);



#endif /* BITCOIN_H_ */
