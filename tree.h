/*
 * tree.h
 *
 *  Created on: 2018-01-18
 *      Author: malego
 */

#ifndef TREE_H_
#define TREE_H_


#include "common.h"
#include "art.h"

enum command_enum{
	TREE_ADD_KEY,
	TREE_COMPARE_KEY,
	TREE_LOAD_FROM_STRING,
	TREE_LOAD_FROM_BYTES,
	TREE_SAVE
};

int tree_command(enum command_enum command, const unsigned char* value, int key_length, int verbose);



#endif /* TREE_H_ */
