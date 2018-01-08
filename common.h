#ifndef _COMMON_H_
#define _COMMON_H_

#include "stdint.h"

#ifndef _COMMON_C_
	void hex2bin(void* dest, const char* src);
	void hexdump(const char* header, const uint8_t* data, int len);
	void DumpBinBigEndian(void* ptr, int size);
	void byte_swap(unsigned char* out, const uint8_t* in, int len);
#endif

#endif
