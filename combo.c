/*
 * combo.c
 *
 *  Created on: 2018-01-13
 *      Author: malego
 */

#include "combo.h"
#include "pthread.h"
#include "timer.h"
#include "common.h"
#include "privkeys.h"
#include "tree.h"

#define BEST_COMBO_QTY 16

privpub_t best_combo[BEST_COMBO_QTY];
privpub_t worst_combo[BEST_COMBO_QTY] = {{{0xFF},{0xFF},0xFF,0xFF,0xFF,0.0}};
float balances[2000000];
extern int flipping_bit_qty;
extern unsigned char privkey_bin[PRIVATE_KEY_LENGTH];

uint64_t verifyed_qty = 0;


static void combo_shift_down(int idx, privpub_t* list_p);
static void combo_print(privpub_t* combo_p);
static void combo_copy(privpub_t* dest_p, privpub_t* src_p);
static void combo_add(privpub_t*  list_p, uint8_t privkey[PRIVATE_KEY_LENGTH], uint8_t hash_160[PUBLIC_KEY_HASH160_LENGTH], uint32_t match_bit, int thread_id, float balance);

pthread_mutex_t stopMutex = PTHREAD_MUTEX_INITIALIZER;

void combo_init()
{
	memset(best_combo, 0, sizeof(privpub_t)*BEST_COMBO_QTY);
	memset(worst_combo, 0xFF, sizeof(privpub_t)*BEST_COMBO_QTY);
}

void combo_verify(unsigned char * privkey_p, unsigned char * hash160_p, int thread_id)
{

	int i, j, ret;

	ret = pthread_mutex_lock(&stopMutex);
	if (ret) { /* an error has occurred */
	    perror("pthread_mutex_lock");
	    pthread_exit(NULL);
	}

	//printf("Thread %d In\n", thread_id);
	for (i=0 ; i<BATCH_SIZE ; i++)
	{
		// We have 2 pubkey for each private key to verify
		for (j=0 ; j<2 ; j++)
		{
			ret = tree_command(TREE_COMPARE_KEY, hash160_p, 20, 1);
			verifyed_qty++;
			if(ret > best_combo[BEST_COMBO_QTY-1].bit_matched)
			{
				combo_add(best_combo, privkey_p, hash160_p, ret, thread_id, 0.0);
			}
			if(ret < worst_combo[BEST_COMBO_QTY-1].bit_matched)
			{
				combo_add(worst_combo, privkey_p, hash160_p, ret, thread_id, 0.0);
			}
			hash160_p += PUBLIC_KEY_HASH160_LENGTH;
		}
		privkey_p += PRIVATE_KEY_LENGTH;
	}
	//printf("Thread %d Out\n", thread_id);

	ret = pthread_mutex_unlock(&stopMutex);
	if (ret) { /* an error has occurred */
	    perror("pthread_mutex_unlock");
	    pthread_exit(NULL);
	}

	return ;
}


static void combo_add(privpub_t*  list_p, uint8_t privkey[PRIVATE_KEY_LENGTH], uint8_t hash_160[PUBLIC_KEY_HASH160_LENGTH], uint32_t match_bit, int thread_id, float balance)
{
	for (int i = 0 ; i < BEST_COMBO_QTY ; i++){
		if (match_bit > best_combo[i].bit_matched){
			combo_shift_down(i, list_p);
			memcpy(list_p[i].privkey, privkey, PRIVATE_KEY_LENGTH);
			memcpy(list_p[i].hash160, hash_160,PUBLIC_KEY_HASH160_LENGTH);
			list_p[i].timestamp = time(NULL);
			list_p[i].bit_matched = match_bit;
			list_p[i].thread_id = thread_id;
			list_p[i].balance = balance;

			//printf("New Top 256 hash160 : ");
			//combo_print(&best_combo[i]);
			return;
		}
	}

}

void combo_print_best_match()
{
	printf("Best up to date : ");combo_print(&best_combo[0]);
}

void combo_print_worst_match()
{
	printf("Worst up to date : ");combo_print(&worst_combo[0]);
}

void combo_print_best_list()
{
	for (int i = BEST_COMBO_QTY-1 ; i >=0 ; i--){
		combo_print(&best_combo[i]);
	}
	printf("Top 256keys list printed, Best at bottom.\n");
}

void combo_print_worst_list()
{
	for (int i = BEST_COMBO_QTY-1 ; i >=0 ; i--){
		combo_print(&worst_combo[i]);
	}
	printf("Worst 256keys list printed, Worst at bottom.\n");
}

static void combo_shift_down(int idx, privpub_t * list_p)
{
	for (int i = BEST_COMBO_QTY-1 ; i >idx ; i--){
		combo_copy(list_p+i, list_p+i-1);
	}
}

static void combo_copy(privpub_t* dest_p, privpub_t* src_p)
{
	memcpy(dest_p->privkey, src_p->privkey, PRIVATE_KEY_LENGTH);
	memcpy(dest_p->hash160, src_p->hash160,PUBLIC_KEY_HASH160_LENGTH);
	dest_p->timestamp = src_p->timestamp;
	dest_p->bit_matched = src_p->bit_matched;
	dest_p->thread_id = src_p->thread_id  ;
	dest_p->balance   = src_p->balance    ;
}

static void combo_print(privpub_t* combo_p)
{
	struct tm tm = *localtime(&combo_p->timestamp);
	printf("Match=%d/160 Bal=%1.2f Thread=%d Timestamp=%d-%d-%d %d:%d:%d\n", combo_p->bit_matched, combo_p->balance, combo_p->thread_id, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	hexdump_bytes_hn("    Privkey: ", combo_p->privkey, PRIVATE_KEY_LENGTH);
	hexdump_bytes_hn("    Hash160: ", combo_p->hash160, PUBLIC_KEY_HASH160_LENGTH);
}


void combo_print_progress()
{
	static struct timespec clock_start ;
	static uint64_t prev_iter = 0;

    uint64_t iterdiff = verifyed_qty - prev_iter;
	if (iterdiff>=1048576){

	    double batch_time = get_clockdiff_s(clock_start);

	    combo_print_best_list();
	    printf("Progress: Iter=%lu, Time=%4.2fs, HashRate=%.2fkKeys/s flipping=%dbits\n", verifyed_qty, batch_time, iterdiff/batch_time/1000.0, flipping_bit_qty);
	    unsigned char* mask = privkeys_get_mask_bytes();
		hexdump_bytes_hn("Current mask = ", mask, 32);
		hexdump_bytes_hn("Current priv = ", privkey_bin, 32);
		//combo_print_worst_match();
		//combo_print_best_match();

		clock_start = get_clock();
		prev_iter = verifyed_qty;
	}

}

