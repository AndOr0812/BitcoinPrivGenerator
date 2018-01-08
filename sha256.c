/*********************************************************************
* Filename:   sha256.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Implementation of the SHA-256 hashing algorithm.
              SHA-256 is one of the three algorithms in the SHA2
              specification. The others, SHA-384 and SHA-512, are not
              offered in this implementation.
              Algorithm specification can be found here:
               * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
              This implementation uses little endian byte order.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include <memory.h>
#include "sha256.h"
#include <stdio.h>
#include "common.h"

/****************************** MACROS ******************************/
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/
void printctx(SHA256_CTX* ctx);
void printdata(SHA256_CTX* ctx);

void sha256_init_inv(SHA256_CTX *ctx, WORD m[16])
{
	int idx;
	
	ctx->datalen = 0;
	ctx->bitlen = 0;
	
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
	
	ctx->a[63] = ~ctx->state[0] + 1;
	ctx->b[63] = ~ctx->state[1] + 1;
	ctx->c[63] = ~ctx->state[2] + 1;
	ctx->d[63] = ~ctx->state[3] + 1;
	ctx->e[63] = ~ctx->state[4] + 1;
	ctx->f[63] = ~ctx->state[5] + 1;
	ctx->g[63] = ~ctx->state[6] + 1;
	ctx->h[63] = ~ctx->state[7] + 1;
	
	for (idx=0 ; idx<16 ; idx++)
	{
		ctx->m[63-idx] = m[idx];
	}
	for (idx=63-16 ; idx>=0 ; idx--)
	{
		ctx->m[idx] = ctx->m[idx+16] - SIG1(ctx->m[idx+14]) - ctx->m[idx+9] - SIG0(ctx->m[idx+1]);
		//printf("Setting m%d to 0x%08X\n", idx, ctx->m[idx]);
	}

	
}

void sha256_transform_inv(SHA256_CTX* ctx)
{
	int idx=64;

	for (idx=64 ; idx>=1 ; idx--)
	{
		ctx->a[idx-1] = ctx->b[idx];
		ctx->b[idx-1] = ctx->c[idx];
		ctx->c[idx-1] = ctx->d[idx];
		ctx->e[idx-1] = ctx->f[idx];
		ctx->f[idx-1] = ctx->g[idx];
		ctx->g[idx-1] = ctx->h[idx];

		ctx->t2[idx-1] = EP0(ctx->a[idx-1]) + MAJ(ctx->a[idx-1],ctx->b[idx-1],ctx->c[idx-1]);
		ctx->t1[idx-1] = ctx->a[idx] - ctx->t2[idx-1];
		ctx->d[idx-1] = ctx->e[idx] - ctx->t1[idx-1];
		ctx->t1k[idx] = ctx->t1[idx-1] - EP1(ctx->e[idx-1]) - CH(ctx->e[idx-1],ctx->f[idx-1],ctx->g[idx-1]) - k[idx-1];
		//printf("t1=0x%08X, t2=0x%08X, konst=0x%08X\n", t1, t2, konst);
		ctx->h[idx-1] = ctx->t1k[idx]-ctx->m[idx-1]; 
	}
}

int sha256_final_inv(SHA256_CTX *ctx, BYTE hash[])
{
	int i, j;
	for (i = 0, j = 0; i < 16; ++i, j += 4)
	{
		ctx->data[j] = ctx->m[i] >> 24;
		ctx->data[j+1] = ctx->m[i] >> 16;
		ctx->data[j+2] = ctx->m[i] >> 8;
		ctx->data[j+3] = ctx->m[i] ;
	}
	
	ctx->bitlen = 0;
	for (i=0; i<8 ; i++)
	{
		ctx->bitlen |= ctx->data[56+i]<<(56-i*8);
	}

	if (ctx->bitlen >= 448)
	{
		printdata(ctx);
		printf("Damn,bitlen=%llu\n", ctx->bitlen);
		//printf("Damn,bitlen=%X\n", ctx->bitlen);
		return 1;
	}	
	//printf("Youpppi,message is one pass!\n");
	
	//Check if message is delimited with a 1
	unsigned int bytenumber = ctx->bitlen >> 3;
	unsigned int bitnumber = (ctx->bitlen & 0x07) + 1;
	BYTE mask = (1<<(8-bitnumber));
	//printf("bytenumber=%d, bitnumber=%d, mask=0x%08X, databyte=0x%08X, result=0x%08X\n", bytenumber, bitnumber, mask, ctx->data[bytenumber], ctx->data[bytenumber]&mask);
	if ( (ctx->data[bytenumber] & mask) != 1)
	{
		printdata(ctx);
		printf("Damn,message is delimited with a 0!\n");	
		return 1;
	}
	//printf("Youpppi, message is delimited with a 1!\n");

	//Check if the message is zero padded
	for (i=bytenumber ; i<56 ; i++)
	{
		if (ctx->data[i] != 0x00)
		{
			printdata(ctx);
			printf("Damn, message is not zero padded\n");
			return 1;
		}
	}
	printctx(ctx);
	printf("Youpppi!!! message is valid!\n");
	exit(0);
}
void printdata(SHA256_CTX* ctx){
	int i;
	printf("data:0x");
	for (i=0 ; i<64 ; i++){
		if (i==56)printf(" ");
		printf("%02X", ctx->data[i]);
	}
	printf("\n");
}

void printctx(SHA256_CTX* ctx){
	int idx, i;
	for (idx=0 ; idx<64 ; idx++){
		printf("%02d:a=%08X,b=%08X,c=%08X,d=%08X,e=%08X,f=%08X,g=%08X,h=%08X\n", idx, ctx->a[idx], ctx->b[idx], ctx->c[idx], ctx->d[idx], ctx->e[idx], ctx->f[idx], ctx->g[idx], ctx->h[idx]);
	}
	printf("m:");
	for (i=0 ; i<4 ; i++){
		for (idx=0 ; idx<16 ; idx++){
			printf("%d=%08X,", 16*i+idx, ctx->m[16*i+idx]);
		}
		printf("\n");
	}
	printf("data:0x");
	for (i=0 ; i<64 ; i++){
		printf("%02X", ctx->data[i]);
	}
	printf("\n");

}

void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

/*
	printf("state0 = %08X and letter a = %08X\n", ctx->state[0], a);
	printf("state1 = %08X and letter b = %08X\n", ctx->state[1], b);
	printf("state2 = %08X and letter c = %08X\n", ctx->state[2], c);
	printf("state3 = %08X and letter d = %08X\n", ctx->state[3], d);
	printf("state4 = %08X and letter e = %08X\n", ctx->state[4], e);
	printf("state5 = %08X and letter f = %08X\n", ctx->state[5], f);
	printf("state6 = %08X and letter g = %08X\n", ctx->state[6], g);
	printf("state7 = %08X and letter h = %08X\n", ctx->state[7], h);
*/
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
/*
	for (idx=0 ; idx<8 ; idx++){
		printf("result%d = %08X\n", idx, ctx->state[idx]);
	}
*/
	//hexdump("Trs: ", ctx->state, 32);

}

void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}


/*
int set_m(SHA256_CTX *ctx, int i, WORD value, int is_calc)
{
	int ret = 0;
	
	if (ctx->m_isset[i])
	{
		// Value is already set, maybe we are lucky and the value matches and no error.
		if (value == ctx->m[i]) return 0;
		//Value does not match. ERROR, we are trying to set a value wich was already set to another value;
		if (ctx->m_iscalc[i]) return 2;
		//Value was choosen at random, we should be able to try another value.
		return 1; 
	}
	else
	{
		ctx->m[i] = value;
		ctx->m_isset[i] = 1;
		ctx->m_iscalc[i] = is_calc;

		if (i >= 16) 
		{
			ret = choose_m(ctx, i-2);
			if (ret) return ret;
			ret = choose_m(ctx, i-7);
			if (ret) return ret;
			ret = choose_m(ctx, i-15);
			if (ret) return ret;
			WORD konst = ctx->m[i] - SIG1(m[i - 2]) - m[i - 7] - SIG0(m[i - 15]);
			ret = set_m(ctx, i-16, konst, 1);
		}
		else
		{
				printctx(ctx);
				printf("HOURRA!!! That was the message\n");
		}
	}
}

int choose_m(SHA256_CTX *ctx, int i)
{
	
	ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
	define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
	define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
	
	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
		63x00000000 = SIG1(61x00000000) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
	
	
	int ret = 1;
	WORD choosed_value = 0x00000000;
	
	if (ctx->m_isset[i])
	{
		//TODO: Verify validity of the already set value
		return 0;
	}
	else
	{
		//Choose a value, starting from begining
		for(choosed_value = 0x00000000 ; choosed_value <0xFFFFFFFF ; choosed_value++ )
		{
			ret = set_m(ctx, i, choosed_value, 0);
			if (!ret) return 0;
		}
		//No value is possible. Abort.
		return 1;
	}
}
*/