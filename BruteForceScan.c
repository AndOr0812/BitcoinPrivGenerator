#define _BRUTEFORCESCAN_C_ 1

 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
 
#define SHA256_DIGEST_LENGTH 32
#define RIPEMD160_DIGEST_LENGTH 20

unsigned char hashIn[SHA256_DIGEST_LENGTH]; 
int bitTo1 = 0;
int min_mask_len = 2;

void dumpIter(unsigned char hashIn[SHA256_DIGEST_LENGTH])
{
	printf("iter=%ld --------------------------------------------\n", iter);
	DumpBinBigEndian(hashIn, 16);
	printf("\n");
	DumpBinBigEndian(hashIn+16, 16);
	printf("\n");
	printf("---------------------------------------------------\n");
	
}

uint64_t Get_mask_left_64bit(int mask_len, int mask_offset)
{
	uint64_t mask = 0;
	int i;
	for (i=0 ; i<mask_len ; i++)
	{
		mask |= 0x1<<64-i-1-mask_offset;
	}
	return mask;
}
uint64_t Get_mask_right_64bit(int mask_len, int mask_offset)
{
	uint64_t mask = 0;
	int i;
	for (i=0 ; i<mask_len ; i++)
	{
		mask |= 0x1<<i+mask_offset;
	}
	return mask;
}

def flip(mask_length, old_mask, word_length, startbit, endbit, level):
		mask = old_mask | create_mask(mask_length, mask_offset, word_length, "left") 
		mask &= create_mask(word_length)	
		if level == 1:
			yield mask
		else:
			yield from flip(mask_length, mask, word_length, mask_offset+mask_length, endbit+mask_length, level-1)

uint64_t * Get_masks(int command )
{
	static int mem_offset[64];
	int mask_offset, i;
	uint64_t mask = 0;

	if (command == CMD_INIT)
	{
		for(
	}

	for (mask_offset=start_bit ; mask_offset<=end_bit ; mask_offset++)
	{
		mem_offset[level] = mask_offset;
		mask = old_mask | Get_mask_left_64bit();
	}
}

void* ProcessBits(int startBit, int endBit, int level){
	int idx;
	int hashValid;
	int bit, B, b;
	static int mem[128][3] = {{0,0,0}};

	for (bit=startBit ; bit<=endBit ; bit++){
		B = bit >> 3;
		b = bit & 0x7;
		hashIn[B] ^= 0x80>>b;

		if (level == 1){
			iter++;
			//hexdump(hashIn, SHA256_DIGEST_LENGTH);
				//same as above
			sha256_init(&sha256_pass2);
			sha256_update(&sha256_pass2, hashIn, SHA256_DIGEST_LENGTH);
			sha256_final(&sha256_pass2, hash2);
			   
			hashValid = 1;
			for (idx = 28 ; idx <SHA256_DIGEST_LENGTH ; idx++){
				if (hash2[idx] != 0) {
					hashValid=0 ;
					break;
				}
			}
			
			if (iter%(1UL<<24) == 0)
			//if (iter == 385)
				dumpIter(hashIn);
			if (hashValid){
				printf("Success!!!!\n");
				hexdump(hashIn, SHA256_DIGEST_LENGTH);
				printf("From\n");
				hexdump(hash2, SHA256_DIGEST_LENGTH);
				
			}else{
				//printf(".");
			}
		}else{
			testCombinations(bit+1, endBit+1, hashIn, level-1);
		}
		hashIn[B] ^= 0x80>>b;
	}

}

void* GetBits()
{
	int bitTo1 = 128;
	memset(hashIn, 0, RIPEMD160_DIGEST_LENGTH);
	testCombinations(0, 256-bitTo1, bitTo1);
}


