#ifndef _COMMON_H_
#define _COMMON_H_

#include "stdint.h"

#ifndef _COMMON_C_
	void hex2bin(void* dest, const char* src);
	void bin2hex(char*out_p, unsigned char*in_p, int len);
	void hexdump(const char* header, const uint8_t* data, int len);
	void DumpBinBigEndian(void* ptr, int size);
	void byte_swap(unsigned char* out, const uint8_t* in, int len);
#endif

#endif
