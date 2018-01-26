/*
 * tree.c
 *
 *  Created on: 2018-01-18
 *      Author: Marc-Andre Legault
 *      Fixed length pubkey lookup table
 */

#include "tree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int save_key(void *file_p, const unsigned char *key, uint32_t key_len, void *value);
static int tree_save_to_file(art_tree* tree_p, const char *dest_filename);
static void tree_load_from_file_bytes(const char* src_filename, int print_progress);
static void tree_load_from_file_string(const char* src_filename, int print_progress);

extern int art_best_depth;


// Call with keylength=0 to save to file, with key_buf =filename
int tree_command(enum command_enum command, const unsigned char* value, int key_length, int verbose)
{
	static art_tree tree;
	static art_tree* tree_p = NULL;
	static int total_qty = 0;
	static int unique_qty = 0;
	static int duplicate_qty = 0;
	void*  ret_p;
	uintptr_t val;

	if (tree_p == NULL)
	{
		tree_p = &tree;
		if ( art_tree_init(tree_p) !=0 ){
			printf("Error init ART Tree\n");
			exit(1);
		}
	}

	switch (command)
	{
	case TREE_ADD_KEY:
		ret_p = art_insert(tree_p, value, key_length, (void*)1);
		total_qty++;
		if ( ret_p != NULL ){
			duplicate_qty++;
			//if (verbose) printf("Duplicate P:%p  Key: %s\n", ret_p, key_buf);
		}
		else{
			unique_qty++;
		}
		if ( total_qty % (512*1024) == 0 ){
			if (verbose)
			{
				printf("Progress %d Key, %d unique, %d duplicate: ", total_qty, unique_qty, duplicate_qty);
				hexdump_bytes_hn("", value, key_length);
			}
		}
		break;

	case TREE_COMPARE_KEY:
		val = (uintptr_t)art_search(tree_p, value, 20);
		if (val){
			//Found exact match
			return 160;
		}
		else{
			//Return best match len
			return art_best_depth;
		}

	case TREE_LOAD_FROM_STRING:
		tree_load_from_file_string(value, verbose);
		break;
	case TREE_LOAD_FROM_BYTES:
		tree_load_from_file_bytes(value, verbose);
		break;

	case TREE_SAVE:
		tree_save_to_file(tree_p, value);
		break;

	}

	return 0;
}



static void tree_load_from_file_bytes(const char* src_filename, int print_progress)
{
	unsigned char linebuf[1024*21];
	int ret, key_length = 20;

    FILE *file_p = fopen(src_filename, "r");
	if (file_p == NULL)
	{
		printf("Can't open file %s for wrting.\n", src_filename);
		exit(1);
	}
	printf("Loading lookup table from file %s.\n", src_filename);

    ret = fread(linebuf, 20, 1024, file_p);
    while (ret > 0) {
    	for (int i=0 ; i<ret ; i++)
    	{
    		tree_command(TREE_ADD_KEY, &linebuf[i*20], key_length, print_progress);
    	}
        ret = fread(linebuf, 20, 1024, file_p);
    }

}

static void tree_load_from_file_string(const char* src_filename, int print_progress)
{
	char linebuf[1024*21];
	char* lineret;
	char* hash160;
	unsigned char hash160_bin[20];
	int key_length = 20;

    FILE *file_p = fopen(src_filename, "r");
	if (file_p == NULL)
	{
		printf("Can't open file %s for reading.\n", src_filename);
		exit(1);
	}
	printf("Loading lookup table from file %s.\n", src_filename);

	lineret = fgets(linebuf, sizeof(linebuf), file_p);
    while (lineret != NULL) {
    	hash160 = strtok(linebuf, " ,.\n");
    	hash160 = strtok(NULL, " ,.\n");
    	hex2bin(hash160_bin, hash160);
    	tree_command(TREE_ADD_KEY, hash160_bin, key_length, print_progress);
   		lineret = fgets(linebuf, sizeof(linebuf), file_p);
    }
}


static int tree_save_to_file(art_tree* tree_p, const char *dest_filename)
{
	static FILE * file_p = NULL;

	if (file_p == NULL)
	{
		file_p = fopen(dest_filename, "w");
		if (file_p == NULL)
		{
			printf("Can't open file %s for wrting.\n", dest_filename);
			exit(1);
		}
	}
	printf("Saving tree in file %s\n", dest_filename);
	art_iter(tree_p, save_key, file_p);
	return 0;
}

static int save_key(void *file_p, const unsigned char *key, uint32_t key_len, void *value)
{
	//printf("Saving key %.*s\n", key_len, key);
	fwrite(key, key_len, 1, (FILE*)file_p);
	return 0;
}
