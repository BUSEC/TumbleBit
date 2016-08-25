#include "random.h"

unsigned char * get_random(int bits){
  BN_CTX *ctx;
  BIGNUM *r = NULL;
  unsigned char * r_str = NULL;
  int r_len;

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    printf("get_random: Couldn't get new CTX\n");
    return NULL;
  }
  BN_CTX_start(ctx);
  r = BN_CTX_get(ctx);

  //https://www.openssl.org/docs/manmaster/crypto/BN_rand.html
  int s = BN_rand(r, bits, 0, 1);
  if (s == 0) {
    printf("get_random: Couldn't generate random number\n");
    return NULL;
  }

  r_len = BN_num_bytes(r);
  r_str = (unsigned char *) tmalloc(r_len);
  BN_bn2bin(r, r_str);

  BN_free(r);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  return r_str;
}

unsigned char * get_random(int bits, BIGNUM *n){
  BN_CTX *ctx;
  BIGNUM *r = NULL;
  unsigned char * r_str = NULL;

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    printf("get_random: Couldn't get new CTX\n");
    return NULL;
  }
  BN_CTX_start(ctx);
  r = BN_CTX_get(ctx);

  //https://www.openssl.org/docs/manmaster/crypto/BN_rand.html
  int s = BN_rand_range(r, n);
  if (s == 0) {
    printf("get_random: Couldn't generate random number\n");
    return NULL;
  }

  BN_num_bytes(r);
  r_str = (unsigned char *) tmalloc(bits / 8);
  BNToBin(r, r_str, bits / 8);

  BN_free(r);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  return r_str;
}
