#include "blind_rsa.h"

#define PUBLIC  "./keys/public_"
#define PRIVATE "./keys/private_"
#define EXT     ".pem"

//============================================================================
//======= Key Generation and Loading
//============================================================================

bool generate_rsa_key(int bits, char* public_suffix, char* private_suffix)
{

  int ret = 0;
  RSA *r = NULL;
  BIGNUM *bne = NULL;
  BIO *bp_public = NULL, *bp_private = NULL;
  unsigned long e = RSA_F4;

  // 1. Generate RSA key
  bne = BN_new(); // init BIGNUM struct
  ret = BN_set_word(bne, e); // set bne to e
  if (ret != 1)
  {
    printf("generate_rsa_key: Couldn't set e");
    goto free_all;
  }

  r = RSA_new();
  ret = RSA_generate_key_ex(r, bits, bne, NULL);
  if (ret != 1)
  {
    printf("generate_rsa_key: Couldn't generate RSA keys");
    goto free_all;
  }

  // 2. Save public key
  char *public_filename;
  asprintf (&public_filename, "%s%d_%s%s", PUBLIC, bits, public_suffix, EXT);

  bp_public = BIO_new_file(public_filename, "w+");
  tfree(public_filename);
  ret = PEM_write_bio_RSAPublicKey(bp_public, r);
  if (ret != 1)
  {
    printf("generate_rsa_key: Couldn't save public key");
    goto free_all;
  }

  // 3. Save private key
  char *private_filename;
  asprintf (&private_filename, "%s%d_%s%s", PRIVATE, bits, private_suffix, EXT);

  bp_private =  BIO_new_file(private_filename, "w+");
  tfree(private_filename);
  ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

  // 4. free
  free_all:
  BIO_free_all(bp_public);
  BIO_free_all(bp_private);
  RSA_free(r);
  BN_free(bne);

  return (ret == 1);
}

RSA * get_public_rsa(int bits, char* suffix){
  RSA *rsa = NULL;
  rsa = RSA_new();

  char *public_filename;
  asprintf (&public_filename, "%s%d_%s%s", PUBLIC, bits, suffix, EXT);

  // Setup signer info
  FILE *fp_public = fopen(public_filename , "r");

  if (fp_public == NULL ) {

    // Generate key of size bits
    generate_rsa_key(bits, suffix, suffix);
    fp_public = fopen(public_filename, "r");

    if (fp_public == NULL){
      tfree(public_filename);
      return NULL;
    }
  }

  PEM_read_RSAPublicKey(fp_public, &rsa, NULL, NULL);

  // Cleanup
  fclose(fp_public);
  tfree(public_filename);

  // Blind key
  int s = RSA_blinding_on(rsa, NULL);
  if (s != 1){
    return NULL;
  }

  return rsa;
}

RSA * get_private_rsa(int bits,  char* suffix){
  RSA *rsa = NULL;
  rsa = RSA_new();

  char *public_filename;
  asprintf(&public_filename, "%s%d_%s%s", PUBLIC, bits, suffix, EXT);

  char *private_filename;
  asprintf(&private_filename, "%s%d_%s%s", PRIVATE, bits, suffix, EXT);

  // Setup signer info
  FILE *fp_public = fopen(public_filename, "r");
  FILE *fp_private = fopen(private_filename, "r");

  if (fp_public == NULL || fp_private == NULL) {

    // Generate key of size bits then try again
    generate_rsa_key(bits, suffix, suffix);
    fp_public  = fopen(public_filename , "r");
    fp_private = fopen(private_filename, "r");

    if (fp_public == NULL || fp_private == NULL){
      return NULL;
    }

  }

  PEM_read_RSAPublicKey(fp_public, &rsa, NULL, NULL);
  PEM_read_RSAPrivateKey(fp_private, &rsa, NULL, NULL);

  // Cleanup
  fclose(fp_public);
  fclose(fp_private);

  tfree(public_filename);
  tfree(private_filename);

  // Blind key
  int s = RSA_blinding_on(rsa, NULL);
  if (s != 1){
    return NULL;
  }

  return rsa;
}

//============================================================================
//======= Blinding Functions
//============================================================================

// Mostly taken from RSA_setup_blinding in rsa_crpt.c
BN_BLINDING * setup_blinding(RSA *rsa) {

  if (!rsa){
    return NULL;
  }

  BIGNUM *e;
  BN_CTX *ctx;
  BN_BLINDING *ret = NULL;

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    printf("setup_blinding: Couldn't get new CTX\n");
    return NULL;
  }
  BN_CTX_start(ctx);

  // Make space for e
  e = BN_CTX_get(ctx);
  if (e == NULL) {
    printf("setup_blinding: Couldn't malloc space for e\n");
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return NULL;
  }

  // Get e
  if (rsa->e == NULL) {
    printf("setup_blinding: Couldn't retrieve e\n");
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return NULL;
  } else {
    e = rsa->e;
  }


  BIGNUM *n;
  n = rsa->n;
  ret = BN_BLINDING_create_param(NULL, e, n, ctx, rsa->meth->bn_mod_exp,
    rsa->_method_mod_n);


    if (ret == NULL) {
      printf("setup_blinding: Couldn't create blinding parameters\n");
    }

    if (ctx != NULL){
      BN_CTX_end(ctx);
      BN_CTX_free(ctx);
    }

    return ret;
  }

  BN_BLINDING * setup_blinding(RSA *rsa, Bin* r) {

    int s;

    BN_BLINDING *blind = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *A   = NULL;
    BIGNUM *Ai  = NULL;
    BIGNUM *rr  = NULL;

    // Setup
    ctx = BN_CTX_new();
    if (ctx == NULL){
      printf("setup_blinding: Failed to get ctx\n");
      return NULL;
    }
    BN_CTX_start(ctx);

    A = BN_new();
    Ai = BN_new();
    rr = BN_new();

    // Convert r
    if (BN_bin2bn(r->data, r->len, rr) == NULL){
      printf("setup_blinding: Failed to convert r\n");
      goto err;
    }

    // Inverse r
    Ai = BN_mod_inverse(Ai, rr, rsa->n, ctx);
    if (Ai == NULL){
      printf("setup_blinding: Failed to invert r\n");
      goto err;
    }

    // Raise to the pk
    s = BN_mod_exp(A, rr, rsa->e, rsa->n, ctx);
    if (s != 1){
      printf("setup_blinding: Failed to get r^pk\n");
      goto err;
    }

    // Setup blinding
    blind = BN_BLINDING_new(A, Ai, rsa->n);

    // Cleanup
    err:
    if (rr != NULL){
      BN_free(rr);
    }

    if (A != NULL){
      BN_free(A);
    }

    if (Ai != NULL){
      BN_free(Ai);
    }

    if (ctx != NULL){
      BN_CTX_end(ctx);
      BN_CTX_free(ctx);
    }

    return blind;
  }

  bool blind(BN_BLINDING * blinding, Bin* msg, Bin* blinded){

    if (blinding == NULL || !defined(msg) || !defined(blinded)){
      return false;
    }

    // Setup
    int r = 0;
    BN_CTX *ctx;
    BIGNUM *f;
    if ((ctx = BN_CTX_new()) == NULL){
      return false;
    }

    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    if (f == NULL){
      return false;
    }

    // Convert to BN
    if (BN_bin2bn(msg->data, msg->len,  f) == NULL){
      return false;
    }

    // Blind
    r = BN_BLINDING_convert_ex(f, NULL, blinding, ctx);
    if (r != 1 ) {
      printf("blind: Couldn't blind message\n");
      goto err;
    }

    // Convert back to bin
    BNToBin(f, blinded->data, blinded->len);

    // Cleanup
    err:
    if(f != NULL){
      BN_free(f);
    }
    if (ctx != NULL){
      BN_CTX_end(ctx);
      BN_CTX_free(ctx);
    }

    return r == 1;
  }


  bool unblind(BN_BLINDING * blinding, Bin* msg, Bin* unblinded){

    if (blinding == NULL || !defined(msg)|| !defined(unblinded)){
      return false;
    }

    // Setup
    int r = 0;
    BN_CTX *ctx;
    BIGNUM *f;

    // Get ctx
    ctx = BN_CTX_new();
    if (ctx == NULL){
      return false;
    }
    BN_CTX_start(ctx);

    f = BN_CTX_get(ctx);
    if (f == NULL){
      goto err;
    }

    // Convert to BN
    if (BN_bin2bn(msg->data, msg->len,  f) == NULL){
      goto err;
    }

    // Unblind
    r =  BN_BLINDING_invert_ex(f, NULL, blinding, ctx);
    if (r != 1 ) {
      printf("unblind: Couldn't blind message\n");
      goto err;
    }

    // Convert back to bin
    BNToBin(f, unblinded->data, unblinded->len);

    // Cleanup
    err:
    if (f != NULL){
      BN_free(f);
    }
    if (ctx != NULL){
      BN_CTX_end(ctx);
      BN_CTX_free(ctx);
    }

    return r == 1;
  }

  bool revert_blind(RSA *rsa, Bin* message, Bin* A, Bin* reverted){

    if (message->data == NULL || A->data == NULL || reverted->data == NULL || reverted->len != message->len){
      return false;
    }

    // Setup
    int r = 0;
    BN_CTX *ctx;
    BIGNUM *m = NULL;
    BIGNUM *a = NULL;

    // Get ctx
    ctx = BN_CTX_new();
    if (ctx == NULL){
      return false;
    }
    BN_CTX_start(ctx);

    // init
    a = BN_CTX_get(ctx);
    if (a == NULL){
      goto err;
    }

    m = BN_CTX_get(ctx);
    if (m == NULL){
      goto err;
    }

    // Convert to BN
    if (BN_bin2bn(message->data, message->len,  m) == NULL){
      printf("revert_blind: Couldn't convert M to bn\n");
      goto err;
    }

    if (BN_bin2bn(A->data, A->len,  a) == NULL){
      printf("revert_blind: Couldn't convert A to bn\n");
      goto err;
    }

    // Invert A
    a = BN_mod_inverse(a, a, rsa->n, ctx);
    if (a == NULL){
      printf("revert_blind: Failed to invert a\n");
      goto err;
    }

    // Multiply
    r = BN_mod_mul(m, m, a, rsa->n, ctx);
    if (r != 1 ) {
      printf("revert_blind: Couldn't multiply bn\n");
      goto err;
    }

    // Convert back to bin
    BNToBin(m, reverted->data, reverted->len);

    // Cleanup
    err:
    if (a != NULL){
      BN_free(a);
    }

    if (m != NULL){
      BN_free(m);
    }

    if (ctx != NULL){
      BN_CTX_end(ctx);
      BN_CTX_free(ctx);
    }

    return r == 1;
  }


  //============================================================================
  //======= RSA Signing & Verification
  //============================================================================

  bool verify(RSA *rsa, Bin* msg, Bin* sig){
    if (!rsa || !defined(msg) || !defined(sig) || sig->len != RSA_size(rsa)) {
      return false;
    }

    unsigned char decrypted[sig->len];

    int r = RSA_public_decrypt(sig->len, sig->data, decrypted, rsa, RSA_NO_PADDING);
    if (r < 0 || r != sig->len) {
      printf("verify: Failed to decrypt\n");
      return false;
    }

    // compare the result
    return memcmp(msg->data, decrypted, msg->len) == 0;
  }

  bool sign(RSA *rsa, Bin* msg, Bin* sig) {
    if (!rsa || !defined(msg) || !defined(sig) || sig->len != RSA_size(rsa)) {
      return false;
    }

    // Sign
    int out_len = RSA_private_encrypt(msg->len, msg->data, sig->data, rsa, RSA_NO_PADDING);
    return out_len != -1;
  }

  //============================================================================
