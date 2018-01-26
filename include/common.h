#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdint.h>



	//----------------------------------------------------
	// MEMORY Manipulation functions
	//----------------------------------------------------
	int memcmp_pos(void* inl, void* inr, int len);
	void memcpy_swap32(void* dest, void* src, int len);
	void bytes_to_file(int file, char* str, int len);
	void str_to_file(int file, char* str);
	void strline_to_file(int file, char* str);

	//----------------------------------------------------
	// HEXADECIMAL Manipulation functions
	//----------------------------------------------------
	void hex2bin(void* dest, const char* src);
	void bin2hex(char*out_p, unsigned char*in_p, int len);
	void hexdump_bytes_hn(const char* header, void* data_p, int len);
	void hexdump_uint32_hn(const char* header, uint32_t* data_p, int len);
	void DumpBinBigEndian(void* ptr, int size);
	
	//----------------------------------------------------
	// BITS Manipulation Functions
	//----------------------------------------------------
	void msg_set_bit(unsigned char* msg, int offset);
	void msg_clear_bit(unsigned char* msg, int offset);
	void msg_flip_bit(unsigned char* msg, int offset);
	int get_bit(unsigned char* msg, int bit_offset);
	int	sprintf_bits(char * dest, void const * const src, int const size);
	char* str_bits(void const * const src, int const size);
	uint64_t Get_mask_left_64bit(int mask_len, int mask_offset);
	uint64_t Get_mask_right_64bit(int mask_len, int mask_offset);
	

	void incr_256bit(uint64_t* p_data, int qty);
	void ProcessBits(unsigned char hashIn[], int startBit, int endBit, int level);


#endif
