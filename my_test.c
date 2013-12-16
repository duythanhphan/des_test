#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "des.h"

static int test_errors = 0;

static int test_assert( int correct, char *test )
{
    if( correct )
        return( 0 );

    test_errors++;
    if( test_errors == 1 )
        printf( "FAILED\n" );
    printf( "  %s\n", test );

    return( 1 );
}

#define TEST_ASSERT( TEST )                         \
        do { test_assert( (TEST) ? 1 : 0, #TEST );  \
             if( test_errors) return;               \
        } while (0)

static int unhexify(unsigned char *obuf, const char *ibuf)
{
    unsigned char c, c2;
    int len = strlen(ibuf) / 2;
    assert(!(strlen(ibuf) %1)); // must be even number of bytes

    while (*ibuf != 0)
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

static void hexify(unsigned char *obuf, const unsigned char *ibuf, int len)
{
    unsigned char l, h;

    while (len != 0)
    {
        h = (*ibuf) / 16;
        l = (*ibuf) % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}


void test_suite_des_encrypt_ecb( char *hex_key_string, char *hex_src_string, char *hex_dst_string ) {
    unsigned char key_str[100];
    unsigned char src_str[100];
    unsigned char dst_str[100];
    des_context ctx;

    memset(key_str, 0x00, 100);
    memset(src_str, 0x00, 100);
    memset(dst_str, 0x00, 100);

    memcpy(key_str, hex_key_string, strlen(hex_key_string) + 1);
    memcpy(src_str, hex_src_string, strlen(hex_src_string) + 1);

    des_setkey_enc( &ctx, key_str);
    TEST_ASSERT( des_crypt_ecb( &ctx, src_str, dst_str ) == 0 );

    memcpy(hex_dst_string, dst_str, strlen(dst_str) + 1);
}


void test_suite_des_decrypt_ecb( char *hex_key_string, char *hex_src_string, char *hex_dst_string ) {
    unsigned char key_str[100];
    unsigned char src_str[100];
    unsigned char dst_str[100];
    des_context ctx;

    memset(key_str, 0x00, 100);
    memset(src_str, 0x00, 100);
    memset(dst_str, 0x00, 100);

    memcpy(key_str, hex_key_string, strlen(hex_key_string) + 1);
    memcpy(src_str, hex_src_string, strlen(hex_src_string) + 1);

    des_setkey_dec( &ctx, key_str);
    TEST_ASSERT( des_crypt_ecb( &ctx, src_str, dst_str ) == 0 );

    memcpy(hex_dst_string, dst_str, strlen(dst_str) + 1);
}


int main(int argc, char **argv) {
	char key[100]  = "0123456789ABCDEF";
	char data[100] = "Security Protocols for OutSourcing Database";

	char encrypted_data[100];
	char decrypted_data[100];

	char data_tmp[10];
	char output[10];

	memset(encrypted_data, 0x00, 100);
	memset(decrypted_data, 0x00, 100);

	memset(data_tmp, 0x00, 10);
	memset(output, 0x00, 10);

	int len  = strlen(data);
	int times_doing = len / 8;
	int remaining = len % 8;
	int i;

	printf("Key  = %s\n", key);
 	printf("Data = %s\n", data);

 	for (i = 0; i < 8 - remaining; i++) {
		strcat(data, "^");
	}
	times_doing++;

 	for (i = 0; i < times_doing; i++) {
 		memset(data_tmp, 0x00, 10);
		memcpy(data_tmp, &data[i*8], 8);
		test_suite_des_encrypt_ecb(key, data_tmp, output);
		strcat(encrypted_data, output);
	}

//	printf("Enc  = ");
//	for (i = 0; i < len; i++) {
//		printf("%02X ", (unsigned char) encrypted_data[i]);
//	}
//	printf("\n");

 	for (i = 0; i < times_doing; i++) {
 		memset(data_tmp, 0x00, 10);
		memcpy(data_tmp, &encrypted_data[i*8], 8);
		test_suite_des_decrypt_ecb(key, data_tmp, output);
		strcat(decrypted_data, output);
	}

 	i = strlen(decrypted_data) - 1;
 	while (decrypted_data[i] == '^') i--;
 	decrypted_data[i+1] = '\0';

	printf("Dec  = %s\n", decrypted_data);

	return 0;
}
