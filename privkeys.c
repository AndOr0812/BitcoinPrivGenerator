/*
 * helper.c
 *
 *  Created on: 2018-01-13
 *      Author: malego
 */

#include "privkeys.h"
#include "combo.h"
#include "timer.h"
#include "pthread.h"

#include <fcntl.h> // for open
#include <unistd.h> // for close



pthread_mutex_t helpMutex = PTHREAD_MUTEX_INITIALIZER;
const char * privkey = "2A5D61CAC54009964313C028FB14350BE19FBA547A1DD2BC9CF954C5EE565EB0";
unsigned char privkey_bin[PRIVATE_KEY_LENGTH];
int flipping_bit_qty = 1;
int flipping_bit_pos[128] = {0};



void rotate_array(unsigned char privkey_bin[PRIVATE_KEY_LENGTH])
{
	uint64_t temp_bit = *(uint64_t*)privkey_bin & 0x0000000000000001;
	*(uint64_t*)privkey_bin >>= 1;
	//printf("Word1 = %.16lX\n", *(uint64_t*)privkey_bin);
	*(uint64_t*)privkey_bin |= ((*(uint64_t*)(&privkey_bin[8])) & 0x0000000000000001)<<63;
	*(uint64_t*)&privkey_bin[8] >>= 1;
	//printf("Word1 = %.16lX\n", *(uint64_t*)&privkey_bin[8]);
	*(uint64_t*)&privkey_bin[8] |= ((*(uint64_t*)(&privkey_bin[16])) & 0x0000000000000001)<<63;
	*(uint64_t*)&privkey_bin[16] >>= 1;
	*(uint64_t*)&privkey_bin[16] |= ((*(uint64_t*)(&privkey_bin[24])) & 0x0000000000000001)<<63;
	//printf("Word1 = %.16lX\n", *(uint64_t*)&privkey_bin[16]);
	*(uint64_t*)&privkey_bin[24] >>= 1;
	*(uint64_t*)&privkey_bin[24] |= temp_bit<<63;
	//printf("Word1 = %.16lX\n", *(uint64_t*)&privkey_bin[24]);
}



void privkeys_generate_from_flipping_mask(uint64_t *privkey_out, int batch_size)
{
	static int msb_at_end_of_travel = 0;
	int b, ret;

	ret = pthread_mutex_lock(&helpMutex);
	if (ret) { /* an error has occurred */
	    perror("pthread_mutex_lock");
	    pthread_exit(NULL);
	}

	for (int i=0 ; i<batch_size ; i++)
	{
		memcpy(&privkey_out[i*4], privkey_bin, 32);
		// Puts all the bits in the Privkey
		for (b=0 ; b<flipping_bit_qty ; b++){
			msg_flip_bit((unsigned char*)&privkey_out[i*4], flipping_bit_pos[b]);
		}

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
	ret = pthread_mutex_unlock(&helpMutex);
	if (ret) {
	    perror("pthread_mutex_unlock");
	    pthread_exit(NULL);
	}
}

void privkeys_generate_from_flipping_mask_n_rotate(uint64_t *privkey_out, int batch_size, int rotate_after_x_bit)
{
	static int msb_at_end_of_travel = 0;
	static int rotate_cnt = 0;
	int b, ret;

	ret = pthread_mutex_lock(&helpMutex);
	if (ret) { /* an error has occurred */
	    perror("pthread_mutex_lock");
	    pthread_exit(NULL);
	}

	for (int i=0 ; i<batch_size ; i++)
	{
		memcpy(&privkey_out[i*4], privkey_bin, 32);
		// Puts all the bits in the Privkey
		for (b=0 ; b<flipping_bit_qty ; b++){
			msg_flip_bit((unsigned char*)&privkey_out[i*4], flipping_bit_pos[b]);
		}

		// Move the bits around, ready for the next iteration

		//Check if first bit is at end of travel
		if (flipping_bit_pos[0]==255)
		{
			// We initiate a rewind after moving the previous bit 1 step forward
			if (msb_at_end_of_travel == flipping_bit_qty-1)
			{
				// All possibilites are exhausted, we add a new bit
				printf("All possibilites are exhausted for %dbits\n", flipping_bit_qty);
				if (flipping_bit_qty >= rotate_after_x_bit)
				{
					if (rotate_cnt == 256){
						printf("Done 256 rotation\n");
						exit(0);
					}
					printf("Rotating privkey\n");
					flipping_bit_qty = 0;
					rotate_array(privkey_bin);
					rotate_cnt++;
				}
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
	ret = pthread_mutex_unlock(&helpMutex);
	if (ret) {
	    perror("pthread_mutex_unlock");
	    pthread_exit(NULL);
	}
}

void privkeys_generate_from_flipping_one(uint64_t *privkey_out, int batch_size)
{
	static int msb_at_end_of_travel = 0;
	int b, ret;

	ret = pthread_mutex_lock(&helpMutex);
	if (ret) { /* an error has occurred */
	    perror("pthread_mutex_lock");
	    pthread_exit(NULL);
	}

	memset(privkey_out, 0, batch_size*32);
	for (int i=0 ; i<batch_size ; i++)
	{
		// Puts all the bits in the Privkey
		for (b=0 ; b<flipping_bit_qty ; b++){
			msg_flip_bit((unsigned char*)&privkey_out[i*4], flipping_bit_pos[b]);
		}

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
	ret = pthread_mutex_unlock(&helpMutex);
	if (ret) {
	    perror("pthread_mutex_unlock");
	    pthread_exit(NULL);
	}
}

unsigned char * privkeys_get_mask_bytes()
{
	static unsigned char mask[32];
	int ret;

	memset(mask, 0, 32);
	int b;
	for (b=0 ; b<flipping_bit_qty ; b++){
		msg_flip_bit(mask, flipping_bit_pos[b]);
	}

	return mask;
}

void privkeys_save_progress()
{
	char buf[128];
	int ret;
	FILE* retfile;

	ret = pthread_mutex_lock(&helpMutex);
	if (ret) { /* an error has occurred */
	    perror("pthread_mutex_lock");
	    pthread_exit(NULL);
	}

	retfile = freopen("./best.txt", "w", stdout);
	if (retfile == NULL){
		printf("combo_save_progress: Error opening file\n");
		exit(EXIT_FAILURE);
	}

	bin2hex(buf, privkey_bin, 32);
	printf("%s\n", buf);
	bin2hex(buf, privkeys_get_mask_bytes(), 32);
	printf("%s\n", buf);
	combo_print_best_list();

	retfile = freopen("./worst.txt", "w", stdout);
	if (retfile == NULL){
		printf("combo_save_progress: Error opening file\n");
		exit(EXIT_FAILURE);
	}

	bin2hex(buf, privkey_bin, 32);
	printf("%s\n", buf);
	bin2hex(buf, privkeys_get_mask_bytes(), 32);
	printf("%s\n", buf);
	combo_print_worst_list();

	retfile = freopen("/dev/tty", "w", stdout);
	if (retfile == NULL){
		printf("combo_save_progress: Error going back to TTY \n");
		exit(EXIT_FAILURE);
	}

	ret = pthread_mutex_unlock(&helpMutex);
	if (ret) {
	    perror("pthread_mutex_unlock");
	    pthread_exit(NULL);
	}

}

int privkeys_load_progress(char* progress_filename)
{
	unsigned char mask[32];
    char * line = NULL;
    size_t buflen ;
    ssize_t readlen;

	printf("combo_load_progress: Loading progress from file : %s\n", progress_filename);

	FILE * f = fopen(progress_filename, "r");
	if (f == NULL){
		printf("combo_load_progress: Progress file not found, starting from scratch\n");
		//Can't read file, we load default privkey and start mask from scratch
		flipping_bit_qty = 1;
		//We initialize the privkey
		hex2bin(privkey_bin, privkey);
		return 1;
	}
	// Getting Privkey
	readlen = getline(&line, &buflen, f);
	if (readlen == -1){
		printf("combo_load_progress: EndOfFile, starting from scratch\n");
		//Can't read file, we load default privkey and start mask from scratch
		flipping_bit_qty = 1;
		//We initialize the privkey
		hex2bin(privkey_bin, privkey);
		return 1;
	}
	hex2bin(privkey_bin, line);

	// Getting Mask
	readlen = getline(&line, &buflen, f);
	if (readlen == -1){
		printf("End of file");
		exit(EXIT_FAILURE);
	}
	hex2bin(mask, line);

	// Processing Mask
	flipping_bit_qty = 0;
	for (int b=255 ; b>=0 ; b--)
	{
		if (get_bit(mask, b) == 1)
		{
			flipping_bit_pos[flipping_bit_qty++] = b;
		}
	}
	if (!flipping_bit_qty) flipping_bit_qty=1;
/*
	printf("Testing rotate\n");
	hexdump_bytes_hn("Original : ",privkey_bin,32);
	for (int i=0 ; i<4 ; i++){
		rotate_array(privkey_bin);
	}
	hexdump_bytes_hn("Rotated  : ",privkey_bin,32);
	*/
	fclose(f);
	printf("combo_load_progress: Sucess\n");
	return 0;
}

void privkeys_print_current()
{
	int ret;

	ret = pthread_mutex_lock(&helpMutex);
	if (ret) { /* an error has occurred */
	    perror("pthread_mutex_lock");
	    pthread_exit(NULL);
	}

	hexdump_bytes_hn("Current Privkey:", privkey_bin, 32);

	ret = pthread_mutex_unlock(&helpMutex);
	if (ret) {
	    perror("pthread_mutex_unlock");
	    pthread_exit(NULL);
	}
}










/*
// Call with a priv_key_hex first to init the function
// Subsequent call should have NULL priv_key_hex so it generate a new incremented privkey
void generate_privkey_incremental(uint64_t *privkey_out, const char *privkeyhex_init, int batch_size)
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

// Call with a privkey_out as NULL first to initialize
// Subsequent call will return a new privkey from a file
static inline void generate_privkey_from_file(uint64_t *privkey_out, uint64_t start_offset, int batch_size)
{
	static FILE * fin = NULL;
    char * line = NULL;
    size_t buflen ;
    ssize_t read;

	if (!fin){
		fin = fopen("/home/malego/Downloads/crackstation.txt", "r");
		if (fin == NULL){
			printf("Error opening file\n");
			exit(EXIT_FAILURE);
		}
		printf("Starting at offset %lu", start_offset);
		fseek(fin, start_offset, SEEK_SET);
		return;
	}

	if (privkey_out != NULL){
		for (int i=0 ; i<batch_size ; i++)
		{
			read = getline(&line, &buflen, fin);
			if (read == -1){
				printf("End of file");
				exit(EXIT_FAILURE);
			}
			//printf("Retrieved read %ld length %zu : %s", read, buflen, line);
			sha256_hash_message((unsigned char *)line, read-1, (unsigned int *)&privkey_out[i*4]);
		}
		free(line);
		return;
	}

	fclose(fin);

}

 */
