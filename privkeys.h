/*
 * helper.h
 *
 *  Created on: 2018-01-13
 *      Author: malego
 */

#ifndef PRIVKEYS_H_
#define PRIVKEYS_H_

#include "common.h"
#include "bitcoin_module.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void privkeys_generate_from_flipping_mask(uint64_t *privkey_out, int batch_size);
void privkeys_generate_from_flipping_mask_n_rotate(uint64_t *privkey_out, int batch_size, int rotate_after_x_bit);
void privkeys_generate_from_flipping_one(uint64_t *privkey_out, int batch_size);
unsigned char *privkeys_get_mask_bytes();
int privkeys_load_progress(char* progress_filename);
void privkeys_save_progress();
void privkeys_print_current();


#endif /* PRIVKEYS_H_ */
