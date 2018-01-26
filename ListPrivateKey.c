
// After building secp256k1_fast_unsafe, compile benchmarks with:
//   gcc -Wall -Wno-unused-function -O2 --std=c99 -march=native -I secp256k1_fast_unsafe/src/ -I secp256k1_fast_unsafe/ ListPrivateKey.c sha256.c common.c RIPEMD160.c timer.c -lgmp -o go

/*
gcc -Wno-unused-function -O2 -march=native -I ../lib/secp256k1_fast_unsafe/ ListPrivateKey.c common.c timer.c RIPEMD160.c ../lib/sha256_asm/sha256-x8664.S -lgmp -o go
gcc -Wno-unused-function -O2 -march=native -I ../lib/secp256k1_fast_unsafe/ ListPrivateKey.c common.c timer.c RIPEMD160.c ../lib/sha256_asm/sha256-x8664.S -lgmp -lart -o goArt
gcc -O2 -march=native -I include -I secp256k1_fast_unsafe/src -I secp256k1_fast_unsafe -I mylibc ListPrivateKey.c combo.c lookup.c pubkeys.c privkeys.c bitcoin_module.c -L. -lsha256 -lmylibc -lgmp -lart -lpthread -o go
*/


#include "RIPEMD160.h"
#include "sha256.h"
#include "common.h"
#include "timer.h"
#include "bitcoin_module.h"
#include "privkeys.h"
#include "pubkeys.h"
#include "combo.h"
#include "tree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include <pthread.h>
#include <signal.h>
#include <getopt.h>
#include <shared_mem.h>



static inline int should_we_stop(uint64_t iter);
static void got_term(int z);
static void got_int(int z);
static void got_usr1(int z);
void *bitcoin_thread(void *param);
void testmask();

int thread_qty = 4;
int got_sigterm = 0;	/* when this TRUE the application must exit */
int got_sigint = 0;	/* when this TRUE the application should exit */
int got_sigusr1 = 0;	/* when set, the application should print stats */


const char start_privkey_hex[256] = "000000006a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321731";
uint64_t max_dump_size = 0;
int max_iter_qty = 0;
uint64_t input_file_start_offset = 10000000000;
FILE *stream_logfile;
char progress_filename[128];

typedef struct{
	int stop;
	int thread_id;

}thread_param_t;

thread_param_t t_params[THREAD_QTY];
pthread_t thread[THREAD_QTY];

int main(int argc, char **argv) {
	int i;

	for (i=0 ; i<thread_qty ; i++)
	{
		t_params[i].stop = 0;
		t_params[i].thread_id = i;
	}

	//testmask();
	//exit(1);

	combo_init();
	tree_command(TREE_LOAD_FROM_BYTES, (const unsigned char *)"/home/malego/Databases/UTXO-12jan2018.bin", 0, 1);
	//tree_command(TREE_SAVE, (const unsigned char *)"/home/malego/Databases/UTXO-12jan2018.bin", 0, 1);
	//Hash160 must exist in bin file : F7A176B831B56DA3AE76A13151814632595AC87F
	if (argc > 1){
		sprintf(progress_filename, "%s", argv[1]);
	}
	else{
		sprintf(progress_filename, "%s", "./best.txt");
	}

	privkeys_load_progress(progress_filename);

	for (i=0 ; i<thread_qty ; i++)
	{
		if ( pthread_create(&thread[i], NULL, bitcoin_thread, &t_params[i]) )
		{
			fprintf(stderr, "Error creating thread %d\n", i);
			return 1;
		}
	}

	//for (ret=0 ; ret<5 ; ret++){
	while(1){
		sleep(20);
		combo_print_progress();
		//privkeys_print_current();
		privkeys_save_progress();
	}

	for (i=0 ; i<thread_qty ; i++)
	{
		fprintf(stdout, "Stopping thread %d\n", i);
		t_params[i].stop = 1;
		if ( pthread_join(thread[i], NULL) )
		{
			fprintf(stderr, "Error joining thread %d\n", i);
			return 1;
		}
		else
		{
			fprintf(stdout, "Success joining thread %d\n", i);
		}
	}

}


void *bitcoin_thread(void *param)
{
	unsigned char privkeys[BATCH_SIZE*PRIVATE_KEY_LENGTH];
	unsigned char pubkeys[BATCH_SIZE*PUBLIC_KEY_LENGTH];
	unsigned char hash160keys[BATCH_SIZE*PUBLIC_KEY_HASH160_LENGTH*2];
	thread_param_t* param_p = (thread_param_t*)param;

	// Initialize the pubkey module
	generate_pubkeys(NULL, NULL, param_p->thread_id);

	printf("Thread %d Crunching now...\n", param_p->thread_id);
    while(1)
	{
	   // Generate Batch(256) Private keys
    	privkeys_generate_from_flipping_mask_n_rotate((uint64_t*)privkeys, BATCH_SIZE, 4);
        // Generate Batch(256) associated uncompressed public keys
		generate_pubkeys(privkeys, pubkeys, param_p->thread_id);
        // Generate Batch(512) Hash160 from uncompressed/Compressed Pubkeys
		generate_hash160_batch(hash160keys, pubkeys);
		// Verify Hash160 keys against lookup tree
		combo_verify(privkeys, hash160keys, param_p->thread_id);

		if (param_p->stop)break;
    }

    /* terminate the thread */
    pthread_exit(NULL);

}

static inline int should_we_stop(uint64_t iter)
{

	if (max_iter_qty && (iter >= max_iter_qty)) return 1;
	return 0;
}

void testmask()
{
	int flipping_bit_qty = 1;
	int flipping_bit_pos[128] = {0};
	int batch_size = 514;
	int i, b, msb_at_end_of_travel;
	unsigned char mask[32];

	for (i=0 ; i<batch_size ; i++)
	{
		memset(mask, 0, 32);
		// Puts all the bits in the Privkey
		for (b=0 ; b<flipping_bit_qty ; b++){
			msg_flip_bit(mask, flipping_bit_pos[b]);
		}
		hexdump_bytes_hn("Mask = ", mask, 32);

		// Move the bits around, ready for the next iteration

		//Check if first bit is at end of travel
		if (flipping_bit_pos[0]==255)
		{
			// We initiate a rewind after moving the previous bit 1 step forward
			if (msb_at_end_of_travel == flipping_bit_qty-1)
			{
				// All possibilites are exhausted, we add a new bit
				printf("All possibilites are exhausted for %dbits\n", flipping_bit_qty);
				flipping_bit_qty++;
				for(b=0 ; b<flipping_bit_qty ; b++)
					flipping_bit_pos[b]=flipping_bit_qty-b-1;
				msb_at_end_of_travel = 0;
			}else{
				// Move the previous bit 1 step forward
				flipping_bit_pos[msb_at_end_of_travel+1]++;
				// Move the current bit against the previous one
				for (b = msb_at_end_of_travel ; b>=0 ; b--)
				{
					flipping_bit_pos[b] = flipping_bit_pos[b+1]+1;
				}
				// Remeber previous bit position if at end of travel for next iteration
				if(flipping_bit_pos[msb_at_end_of_travel+1] == 255-(msb_at_end_of_travel+1))msb_at_end_of_travel++;
			}
		}
		else
		{
			msb_at_end_of_travel = 0;
			flipping_bit_pos[0]++;
		}
	}

}






static void signal_init()
{
	struct sigaction sv;
	/* set up the signal handling system */
	sigemptyset(&sv.sa_mask);
	sv.sa_flags = 0;
	sv.sa_handler = got_int;
	sigaction(SIGINT, &sv, NULL);
	sv.sa_handler = got_term;
	sigaction(SIGTERM, &sv, NULL);
	sv.sa_handler = got_usr1;
	sigaction(SIGUSR1, &sv, NULL);
	/* ignore some boring signals */
	sv.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sv, NULL);
	sigaction(SIGURG, &sv, NULL);
}

static void got_term(int z)
{
	if (!got_sigterm)
		printf("Terminated.\n");
	printf("_____ RECEIVED SIGTERM _____\n");
	got_sigterm = 1;
	exit(EXIT_FAILURE);
}

static void got_int(int z)
{
	if (!got_sigint)
		printf("Exiting.");
	printf("_____ RECEIVED SIGINT _____ \n");
	got_sigint = 1;
	exit(EXIT_FAILURE);
}

static void got_usr1(int z)
{
	printf("_____ RECEIVED SIGUSR1 _____ \n");
}
