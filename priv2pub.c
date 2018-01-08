
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/ec.h>
#include <openssl/obj_mac.h> // for NID_secp256k1
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

 
 
unsigned char *TestPrivateKeyWif = "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF";
unsigned char *TestPublicKey = "";
unsigned char *TestBitcoinAddress = "1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj";
unsigned char *TestPrivateMiniKey = "SzavMBLoXU6kDrqtUVmffv";

void hex2bin(unsigned char* dest, unsigned char* src);
void hexdump(unsigned char* data, int len);
void byte_swap(unsigned char* data, int len);


// calculates and returns the public key associated with the given private key
// - input private key and output public key are in hexadecimal
// form = POINT_CONVERSION_[UNCOMPRESSED|COMPRESSED|HYBRID]
unsigned char *priv2pub( const unsigned char *priv_hex, point_conversion_form_t form , BIGNUM *pub_bn)
{
	// create group
	EC_GROUP *ecgrp = EC_GROUP_new_by_curve_name( NID_secp256k1 );

	// convert priv key from hexadecimal to BIGNUM
	BIGNUM *priv_bn = BN_new();
	BN_hex2bn( &priv_bn, priv_hex );

	// compute pub key from priv key and group
	EC_POINT *pub = EC_POINT_new( ecgrp );
	EC_POINT_mul( ecgrp, pub, priv_bn, NULL, NULL, NULL );

	// convert pub_key from elliptic curve coordinate to hexadecimal
	unsigned char *ret = EC_POINT_point2hex( ecgrp, pub, form, NULL );
	//EC_POINT_point2bn( ecgrp, pub, form, pub_bn, NULL );
	
	EC_GROUP_free( ecgrp ); BN_free( priv_bn ); EC_POINT_free( pub );

	return ret;
}


int main( int argc, const unsigned char *argv[] )
{
	unsigned char pub_key_bin_uncomp[65];
	unsigned char pub_key_uncomp_hash[32];
	unsigned char pub_key_uncomp_ripemd160[20];
	unsigned char pub_key_uncomp_ripemd160_extended[21];
	unsigned char pub_key_uncomp_ripemd160_ext_checksum[32];
	unsigned char pub_key_uncomp_ripemd160_ext_checksum2[32];
	unsigned char pub_key_uncomp_hex[25];
	
	//Get priv key from cmd line and compute pub key
	//18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
	unsigned char *pub_key_hex_uncomp = priv2pub( argv[1], POINT_CONVERSION_UNCOMPRESSED, NULL );
	printf( "Uncompressed HEX:%s\n", pub_key_hex_uncomp );
	hex2bin(pub_key_bin_uncomp, pub_key_hex_uncomp);

	//Hash SHA256 the public key
	SHA256(pub_key_bin_uncomp, 65, pub_key_uncomp_hash);
	printf("SHA256:");
	hexdump(pub_key_uncomp_hash, 32);

	//
	RIPEMD160(pub_key_uncomp_hash, 32, pub_key_uncomp_ripemd160);
	printf("RIPEMD160:");
	hexdump(pub_key_uncomp_ripemd160, 20);
	
	//Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
	pub_key_uncomp_ripemd160_extended[0] = 0x00;
	memcpy(&pub_key_uncomp_ripemd160_extended[1], pub_key_uncomp_ripemd160, 20);
	printf("Added version 0x00:");
	hexdump(pub_key_uncomp_ripemd160_extended, 21);
	
	//Perform SHA-256 hash on the extended RIPEMD-160 result
	//445C7A8007A93D8733188288BB320A8FE2DEBD2AE1B47F0F50BC10BAE845C094
	SHA256(pub_key_uncomp_ripemd160_extended, 21, pub_key_uncomp_ripemd160_ext_checksum);
	printf("1st Pass Checksum:");
	hexdump(pub_key_uncomp_ripemd160_ext_checksum, 32);
	
	// Perform SHA-256 hash on the result of the previous SHA-256 hash
	//D61967F63C7DD183914A4AE452C9F6AD5D462CE3D277798075B107615C1A8A30
	SHA256(pub_key_uncomp_ripemd160_ext_checksum, 32, pub_key_uncomp_ripemd160_ext_checksum2);
	printf("2nd Pass Checksum:");
	hexdump(pub_key_uncomp_ripemd160_ext_checksum2, 32);
	
	memcpy(pub_key_uncomp_hex, pub_key_uncomp_ripemd160_extended, 21);
	memcpy(&pub_key_uncomp_hex[21], pub_key_uncomp_ripemd160_ext_checksum2, 4);
	printf("Biycoin Address Hex:");
	hexdump(pub_key_uncomp_hex, 25);
	
	
	
	/*
	unsigned char *pub_key_hex_comp = priv2pub( argv[1], POINT_CONVERSION_COMPRESSED, NULL );
	printf( "Compressed HEX:%s\n", pub_key_hex_comp ); 
	unsigned char pub_key_bin_comp[65];
	hex2bin(pub_key_bin_comp, pub_key_hex_comp);	
	unsigned char pub_key_comp_hash[32];
	SHA256(pub_key_bin_comp, 65, pub_key_comp_hash);
	printf("SHA256:");
	hexdump(pub_key_comp_hash, 32);
	unsigned char pub_key_comp_ripemd160[21];
	//Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
	pub_key_comp_ripemd160[0] = 0x00;
	RIPEMD160(pub_key_comp_hash, 32, &pub_key_comp_ripemd160[1]);
	printf("RIPEMD160:");
	hexdump(pub_key_comp_ripemd160, 20);
*/	
	//BN_bn2bin(pub_bn, pub_key_binc);
	//pub2sha256(pub_key_hex, pub_sha256_hash);
	
	free( pub_key_hex_uncomp );
	//free( pub_key_hex_comp );

	return 0;
}



// we need a helper function to convert hex to binary, this function is unsafe and slow, but very readable (write something better)
void hex2bin(unsigned char* dest, unsigned char* src)
{
        unsigned char bin;
        int c, pos;
        char buf[3];
 
        pos=0;
        c=0;
        buf[2] = 0;
        while(c < strlen(src))
        {
                // read in 2 characaters at a time
                buf[0] = src[c++];
                buf[1] = src[c++];
                // convert them to a interger and recast to a char (uint8)
                dest[pos++] = (unsigned char)strtol(buf, NULL, 16);
        }
       
}
 
// this function is mostly useless in a real implementation, were only using it for demonstration purposes
void hexdump(unsigned char* data, int len)
{
        int c;
       
        c=0;
        while(c < len)
        {
                printf("%.2x", data[c++]);
        }
        printf("\n");
}
 
// this function swaps the byte ordering of binary data, this code is slow and bloated (write your own)
void byte_swap(unsigned char* data, int len) {
        int c;
        unsigned char tmp[len];
       
        c=0;
        while(c<len)
        {
                tmp[c] = data[len-(c+1)];
                c++;
        }
       
        c=0;
        while(c<len)
        {
                data[c] = tmp[c];
                c++;
        }
}