/*
  gcc password_cracker.c  -l crypto -o password_cracker.o

  https://github.com/sqlcipher/sqlcipher-tools/blob/master/decrypt.c
  http://blog.csdn.net/lonelyrains/article/details/50837654
  http://www.cnblogs.com/lvpei/archive/2011/02/18/1957804.html
  http://www.cnblogs.com/fuyunbiyi/p/3475602.html
*/

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>


//================
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <time.h>

#define PAGESIZE 1024
#define PBKDF2_ITER 4000
#define DISABLE_HMAC
#define FILE_HEADER_SZ 16

#define TEST_ROUND 2
#define LARGEST_NUM (268435456-1)
#define TRUCK_SIZE 1000



//===================
char* infile ;
//const char* outfile = "decrypted_sqlite.db";
char* passfile ;

const char hex_array[] = "0123456789abcdef";
//===================

// 0x9955bbc
unsigned long pass_sn = 0x9955bbc-2000;

void increse_num(void);
int quit_flag = 0;

int main(int argc, char **argv)
{


    long pass_start;
    long pass_end;
    long x;

    infile = argv[1];
    passfile = argv[2];
    pass_start = strtol(argv[3], NULL, 0); //atoi(argv[1]);
    pass_end = strtol(argv[4], NULL, 0); //atoi(argv[2]);

    char pass[8]= {'0'}; /* two bytes of hex = 4 characters, plus NULL terminator */


    int i, csz, tmp_csz, key_sz, iv_sz, block_sz, hmac_sz, reserve_sz;
    FILE *infh;
    int read;
    unsigned char *inbuffer, *outbuffer, *salt, *out, *key, *iv;
    EVP_CIPHER *evp_cipher;
    EVP_CIPHER_CTX * ectx = EVP_CIPHER_CTX_new(); 

    OpenSSL_add_all_algorithms();

    evp_cipher = (EVP_CIPHER *) EVP_get_cipherbyname("aes-256-cbc");

    key_sz = EVP_CIPHER_key_length(evp_cipher);
    key = malloc(key_sz);

    iv_sz = EVP_CIPHER_iv_length(evp_cipher);
    iv = malloc(iv_sz);

    hmac_sz = EVP_MD_size(EVP_sha1());
#ifdef DISABLE_HMAC
    hmac_sz = 0;
#endif
    block_sz = EVP_CIPHER_block_size(evp_cipher);

    reserve_sz = iv_sz + hmac_sz;
    reserve_sz = ((reserve_sz % block_sz) == 0) ? reserve_sz : ((reserve_sz / block_sz) + 1) * block_sz;

    inbuffer = (unsigned char*) malloc(PAGESIZE);
    outbuffer = (unsigned char*) malloc(PAGESIZE);
    salt = malloc(FILE_HEADER_SZ);

    infh = fopen(infile, "r");
    //outfh = fopen(outfile, "w");
    read = fread(inbuffer, 1, PAGESIZE, infh);  /* read the first page */
    fclose(infh);

    memcpy(salt, inbuffer, FILE_HEADER_SZ); /* first 16 bytes are the random database salt */


    //PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass), salt, FILE_HEADER_SZ, PBKDF2_ITER, key_sz, key);

    memset(outbuffer, 0, PAGESIZE);
    out = outbuffer;

    memcpy(iv, inbuffer + PAGESIZE - reserve_sz, iv_sz); /* last iv_sz bytes are the initialization vector */


    printf("Start from %07x to %07x.\n", pass_start, pass_end );


    clock_t start = clock();
    for (x=pass_start; x<=pass_end && x <= LARGEST_NUM; x++)
    {

        pass[0] = hex_array[((x & 0xF000000) >> 24)];
        pass[1] = hex_array[((x & 0x0F00000) >> 20)];
        pass[2] = hex_array[((x & 0x00F0000) >> 16)];
        pass[3] = hex_array[((x & 0x000F000) >> 12)];
        pass[4] = hex_array[((x & 0x0000F00) >> 8)];
        pass[5] = hex_array[((x & 0x00000F0) >> 4)];
        pass[6] = hex_array[((x & 0x000000F) >> 0)];

        PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass), salt, FILE_HEADER_SZ, PBKDF2_ITER, key_sz, key);
        out = outbuffer;
        EVP_CipherInit(ectx, evp_cipher, NULL, NULL, 0);
        EVP_CIPHER_CTX_set_padding(ectx, 0);
        EVP_CipherInit(ectx, NULL, key, iv, 0);
        EVP_CipherUpdate(ectx, out, &tmp_csz, inbuffer + FILE_HEADER_SZ, PAGESIZE - reserve_sz - FILE_HEADER_SZ);
        csz = tmp_csz;
        out += tmp_csz;
        EVP_CipherFinal(ectx, out, &tmp_csz);
        csz += tmp_csz;
        EVP_CIPHER_CTX_cleanup(ectx);

        // WeChat 7.0 use different write/read version
        // [5] = 64; [6] = 32; [7] = 32; [56:(56+20)] = 0;
        if( outbuffer[5] == 0x40 
            && outbuffer[6] == 0x20 
            && outbuffer[7] == 0x20
            //&& outbuffer[56] == 0x00 
            //&& outbuffer[57] == 0x00
          )
        {
            quit_flag = 1;

            printf("OK\n");
            printf("Pass: %s\n", pass);
            FILE *passfh;

            passfh = fopen(passfile, "a");
            fwrite(pass, 1, strlen(pass), passfh);
            fwrite("\n", 1, strlen("\n"), passfh);
            fclose(passfh);

            printf("outbuffer:\n");
            int kk,kkk;
            for (kk=0; kk<10; kk++)
            {
                for (kkk=0; kkk<10; kkk++)
                {
                    printf("%02x ", outbuffer[kk*10 + kkk]);
                }
                printf("\n");
            }

        }

    }

    clock_t end = clock();
    unsigned long millis = (end - start) * 1000 / CLOCKS_PER_SEC;
    if (millis==0)
        millis = 1;
    float speed = (pass_end+1-pass_start)*1000.0/(millis);

    printf("END from %07x to %07x. Speed: %f/s .\n", pass_start, pass_end, speed );


    free(inbuffer);
    free(outbuffer);
    free(key);
    free(salt);
    free(iv);


    return 0;
}
