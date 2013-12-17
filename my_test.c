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

 	// if length of data > 8, plit it and encode each part
 	// if remaining part is not fit 8 char, add '^' to fit.
 	for (i = 0; i < 8 - remaining; i++) {
		strcat(data, "^");
	}
	times_doing++;

 	for (i = 0; i < times_doing; i++) {
 		memset(data_tmp, 0x00, 10);
		memcpy(data_tmp, &data[i*8], 8);

		// encode data
		test_suite_des_encrypt_ecb(key, data_tmp, output);

		// get ciphertext (encrypted data)
		strcat(encrypted_data, output);
	}

 	// print encrypted data for debugging, some value of encrypted data is not
 	// readable, so print it as hex format.
	printf("Enc  = ");
	for (i = 0; i < len; i++) {
		printf("%02X ", (unsigned char) encrypted_data[i]);
	}
	printf("\n");

 	for (i = 0; i < times_doing; i++) {
 		memset(data_tmp, 0x00, 10);
		memcpy(data_tmp, &encrypted_data[i*8], 8);

		// decode data
		test_suite_des_decrypt_ecb(key, data_tmp, output);

		// get plaintext (decrypted data)
		strcat(decrypted_data, output);
	}

 	// remove '^' character which added before
 	i = strlen(decrypted_data) - 1;
 	while (decrypted_data[i] == '^') i--;
 	decrypted_data[i+1] = '\0';

 	// print decrypted data to console
	printf("Dec  = %s\n", decrypted_data);

	return 0;
}
