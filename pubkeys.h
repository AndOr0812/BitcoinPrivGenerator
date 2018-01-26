/*
 * pubkeys.h
 *
 *  Created on: 2018-01-15
 *      Author: malego
 */

#ifndef PUBKEYS_H_
#define PUBKEYS_H_

#include "common.h"
#include "bitcoin_module.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>




void generate_hash160_batch(unsigned char* hash160keys_p, unsigned char* pubkeys_p);
void Hash_public_key(uint8_t * p_data_out, const uint8_t * p_data_in, const int data_in_len);



#endif /* PUBKEYS_H_ */
