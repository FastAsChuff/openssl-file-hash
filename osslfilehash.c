#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h> //sudo apt-get install libssl-dev

// gcc osslfilehash.c -o osslfilehash.bin -O3 -lcrypto -Wall -march=native


#define OSSL_HASH_DIGEST_NAME "SHA1"
#define OSSL_HASH_DIGEST_LEN 20

uint32_t openssl_file_hash_fn(char*filename, char*rethexhash) {
  char hexnibbles[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  char filebuffer[16384];
  FILE *fp = fopen(filename, "rb");
  if (fp == NULL) return 1;
  size_t bytes = 0;
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();  
  const EVP_MD *md = EVP_get_digestbyname(OSSL_HASH_DIGEST_NAME);
  unsigned char md_value[OSSL_HASH_DIGEST_LEN];
  uint32_t md_len = 0;
  EVP_DigestInit_ex(mdctx, md, NULL);
  do {
    EVP_DigestUpdate(mdctx, filebuffer, bytes);
    bytes = fread(filebuffer, 1, 16384, fp);
    //printf("Read %lu bytes\n", bytes);
  } while (!feof(fp));
  if (bytes > 0) EVP_DigestUpdate(mdctx, filebuffer, bytes);
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_free(mdctx);
  uint32_t i,j;
  j = 0;
  for (i=0; i<OSSL_HASH_DIGEST_LEN; i++) {
    rethexhash[j] = hexnibbles[md_value[i] >> 4];
    j++;
    rethexhash[j] = hexnibbles[md_value[i] & 0xf];
    j++;
  }
  fclose(fp);
  return 0;
}


int main(int argc, char **argv){
  char osslhexhash[2*OSSL_HASH_DIGEST_LEN+1] = {0};
  if (argc < 2) exit(0);
  uint32_t res = openssl_file_hash_fn(argv[1], osslhexhash);
  if (res) {
    printf("Error calculating %s hash of file %s.\n", OSSL_HASH_DIGEST_NAME, argv[1]);
  } else {
    printf("%s of file %s = %s\n", OSSL_HASH_DIGEST_NAME, argv[1], osslhexhash);
  }
}
