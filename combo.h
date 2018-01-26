/*
 * combo.h
 *
 *  Created on: 2018-01-13
 *      Author: malego
 */

#ifndef COMBO_H_
#define COMBO_H_

#include "common.h"
#include "bitcoin_module.h"
#include "art.h"
#include "time.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct{
	uint8_t privkey[32];
	uint8_t hash160[20];
	uint8_t bit_matched;
	uint8_t thread_id;
	time_t timestamp;
	float balance;
}privpub_t;


void combo_init();
void combo_verify(unsigned char * privkey_p, unsigned char * hash160, int thread_id);
void combo_print_best_list();
void combo_print_worst_list();
void combo_print_best_match();
void combo_print_worst_match();
void load_lookup(art_tree* tree_p, char* src_filename, int src_is_hex, int dest_is_hex, int print_progress);
void combo_print_progress();
void combo_save_progress();
int combo_load_progress(int* bit_qty, int bit_pos[128]);


#endif /* COMBO_H_ */
