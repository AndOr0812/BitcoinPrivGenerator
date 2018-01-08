#include "RIPEMD160.h"
#include "ecc.h"
#include "common.h"
#include "sha256.h"

#include <secp256k1.h>

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close


//compile gcc sha256.c common.c ecc.c RIPEMD160.c ListPrivateKey.c -o go -lsecp256k1

uint8_t publicKey_c_le[33];
uint8_t publicKey_u_le[65];
uint8_t result_buf[72];

const uint64_t maxfilesize = 600000000000;
uint64_t filesizeU = 0;
uint64_t filesizeC = 0;
uint64_t iter = 0, previter =0;
static secp256k1_context *ctx = NULL;
secp256k1_pubkey pubkey;
size_t pubkeyclen = 33;
size_t pubkeyulen = 65;
int ret;
int fileDumpC;
int fileDumpU;
unsigned long currtime;
unsigned iterdiff;
unsigned timediff;
unsigned long prevtime;
SHA256_CTX sha256_ctx;



void incr_private_key()
{


	int i = 0;
	while(result_buf[i] == 0xFF)
	{
		result_buf[i]++;
		i++;
	}
	result_buf[i]++;
	iterdiff = iter - previter;
	if (iterdiff==262144)
	{
		currtime = (unsigned long)time(0);
		timediff = currtime-prevtime;
		printf("Iter=%lu, HashRate=%.2fkH/s\n", iter, iterdiff/timediff/1000.0);
		hexdump("Progress=", result_buf, 32);
		printf("\n");
		prevtime = currtime;
		previter = iter;
	}
}




int Get_Public_Key(uint8_t publicKey_c_le[33], uint8_t publicKey_u_le[65])
{
   	ret = secp256k1_ec_pubkey_create(ctx, &pubkey, result_buf);
	if (ret != 1) {
		printf("FAILED1");
		return 1;
	}
	secp256k1_ec_pubkey_serialize(ctx, publicKey_c_le, &pubkeyclen, &pubkey, SECP256K1_EC_COMPRESSED);
	secp256k1_ec_pubkey_serialize(ctx, publicKey_u_le, &pubkeyulen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
	
}

int Dump_to_screen(const char* header, const void * data, const int datalen)
{
	hexdump(header, (const uint8_t *)data, datalen);
}

int main(int argc, char **argv)
{	
	unsigned char filenameU[256];
	unsigned char filenameC[256];
	unsigned char * privkeyhex = "00004cac6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321727";
	hex2bin(result_buf, privkeyhex);
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

	if (argc > 1) {
		sprintf(filenameU, "%sKeys_PrivPubUncompressed_%s.txt", argv[1], privkeyhex);
		sprintf(filenameC, "%sKeys_PrivPubCompressed_%s.txt", argv[1], privkeyhex);
	}else{
		sprintf(filenameU, "/media/malego/Data2TB/Keys_PrivPubUncompressed_%s.txt", privkeyhex);
		sprintf(filenameC, "/media/malego/Data2TB/Keys_PrivPubCompressed_%s.txt", privkeyhex);
	}
	printf("Opening files %s\n", filenameU);
	printf("Opening files %s\n", filenameC);
	fileDumpU = open(filenameU, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if (fileDumpU<=0)
	{
		printf("Error opening file\n");
		return 0;
	}
	fileDumpC = open(filenameC, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if (fileDumpC<=0)
	{
		printf("Error opening file\n");
		return 0;
	}

    if (argc > 2) {
		printf("Starting with private key %s\n", argv[2]);
        int pos = 0;
        const char* ch = argv[2];
        while (pos < 32) {
            unsigned short sh;
            if (sscanf(ch, "%2hx", &sh)) 
			{
                result_buf[pos] = sh;
            } 
			else
			{
				printf("Invalid PrivateKey Provided\n");
				return 0;
            }
            ch += 2;
            pos++;
		}
    }

	prevtime = (unsigned long)time(0);
	while(filesizeU < maxfilesize)
	{
		Get_Public_Key(publicKey_c_le, publicKey_u_le);

		/*
		Dump_to_screen("Private Key  = ", result_buf, 32);
		Dump_to_screen("Pubkey Raw   = ", &pubkey, 65);
		Dump_to_screen("Pubkey U     = ", publicKey_u_le, 65);
		Dump_to_screen("Pubkey C     = ", publicKey_c_le, 33);
		*/


		write(fileDumpC, result_buf, 72);
		write(fileDumpC, publicKey_c_le, 33);
		filesizeC += 72;
		write(fileDumpU, privateKey_le, 32);
		write(fileDumpU, publicKey_u_le, 65);
		filesizeU += 97;

		incr_private_key();

		iter++;
	}
	close(fileDumpC);
	close(fileDumpU);
}


