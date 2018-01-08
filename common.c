#define _COMMON_C_ 1

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"

// we need a helper function to convert hex to binary, this function is unsafe and slow, but very readable (write something better)
void hex2bin(void* dest, const char* src)
{
	uint8_t * dest_p = (uint8_t*)dest;
	int c, pos;
	char buf[3];
	int len = strlen(src);
	pos=0;
	c=0;
	buf[2] = 0;
	while(c < len)
	{
			// read in 2 characaters at a time
			buf[0] = src[c++];
			buf[1] = src[c++];
			// convert them to a interger and recast to a char (uint8)
			dest_p[pos++] = (unsigned char)strtol(buf, NULL, 16);
	}
       
}
 
 void hex_dump(void *data, size_t len) {
    unsigned char *chr = data;
    for ( size_t pos = 0; pos < len; pos++, chr++ ) { printf("%02x ", *chr & 0xFF); }
}

// this function is mostly useless in a real implementation, were only using it for demonstration purposes
void hexdump(const char* header, const uint8_t* data, int len)
{
    int c;
   
	printf("%s", header);

    c=0;
    while(c < len)
    {
            printf("%.2x", data[c++]);
    }
    printf("\n");
}

void DumpBinBigEndian(void* ptr, int size)
{
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i=0;i<size;i++)
    {
        for (j=7;j>=0;j--)
        {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
    }
    puts("");
}
 
// this function swaps the byte ordering of binary data, this code is slow and bloated (write your own)
void byte_swap(unsigned char* out, const uint8_t* in, int len)
{
        int c;
       
        c=0;
        while(c<len)
        {
                out[c] = in[len-(c+1)];
                c++;
        }
       
}

