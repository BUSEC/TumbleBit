#include "ec.h"
#include <string.h>

#define PUBLIC  "./keys/EC_public_"
#define PRIVATE "./keys/EC_private_"
#define PEM     ".pem"
#define BIN     ".bin"

bool generate_EC_key(const char* public_suffix, const char* private_suffix){

    int ret = 0;
    int r = 0;

    BIO *bp_public = NULL, *bp_private = NULL;
    EVP_PKEY *pkey   = NULL;

    //=====================================
    // 1. Generate EC_KEY
    //=====================================

    // Init EC_KEY
    EC_KEY *eckey = EC_KEY_new();
    if (eckey == NULL)
    {
        printf("generate_EC_key: Failed to create new EC Key\n");
        return false;
    }

    // Get Group
    EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (ecgroup == NULL)
    {
        printf("generate_EC_key: Failed to create new EC Group\n");
        return false;
    }

    // Set Group
    r = EC_KEY_set_group(eckey,ecgroup);
    if (1 != r)
    {
        printf("generate_EC_key: Failed to set group for EC Key\n");
        return false;
    }

    // Generate key
    r = EC_KEY_generate_key(eckey);
    if (1 != r)
    {
        printf("generate_EC_key: Failed to generate EC Key\n");
        return false;
    }

    //=====================================
    // 2. Convert EC_KEY to EVP_PKEY
    //=====================================

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey, eckey)){
      printf("generate_EC_key: Failed to convert EC Key\n");
      return false;
    }


    //=====================================
    // 3. Save public key
    //=====================================
    char *public_filename;
    asprintf (&public_filename, "%s%s%s", PUBLIC, public_suffix, PEM);


    bp_public = BIO_new_file(public_filename, "w+");
    free(public_filename);

    ret = PEM_write_bio_PUBKEY(bp_public, pkey);
    if (ret != 1)
    {
      printf("generate_EC_key: Couldn't save public key");
      return false;
    }

    //=====================================
    // 4. Save private key
    //=====================================
    char *private_filename;
    asprintf (&private_filename, "%s%s%s", PRIVATE, private_suffix, PEM);

    bp_private =  BIO_new_file(private_filename, "w+");
    free(private_filename);

    ret = PEM_write_bio_PUBKEY(bp_private, pkey);
    if (ret != 1)
    {
      printf("generate_EC_key: Couldn't save public key");
      return false;
    }

    PEM_write_bio_PrivateKey(bp_private, pkey, NULL, NULL, 0, 0, NULL);
    if (ret != 1)
    {
      printf("generate_EC_key: Couldn't save private key");
      return false;
    }


    //=====================================
    // 5. free
    //=====================================
    if (bp_public != NULL) {
        BIO_free_all(bp_public);
    }

    if (bp_private != NULL) {
        BIO_free_all(bp_private);
    }

    if (ecgroup != NULL){
      EC_GROUP_free(ecgroup);
    }

    if (pkey != NULL){
      EVP_PKEY_free(pkey);
    }

    return (ret == 1);
}

EC_KEY * get_ec_key(const char *key_path, bool private_key){

  EC_KEY *eckey  = NULL;
  EVP_PKEY *pkey = NULL;

  FILE *fp = fopen(key_path, "r");
  if (fp == NULL) {
    printf("get_ec_key: Couldn't open keys for reading\n");
    return NULL;
  }

  if (private_key == true){
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL){
      printf("get_ec_key: Couldn't read key\n");
      return NULL;
    }
  } else {
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL){
      printf("get_ec_key: Couldn't read key\n");
      return NULL;
    }
  }

  eckey = EVP_PKEY_get1_EC_KEY(pkey);
  if (eckey == NULL) {
    printf("get_ec_key: Couldn't convert key to EC_KEY");
    return NULL;
  }

  if (pkey != NULL){
    EVP_PKEY_free(pkey);
  }

  return eckey;
}

EC_KEY * get_ec_key_by_suffix(const char *suffix, bool private_key){
  char *path;
  if (private_key){
    asprintf (&path, "%s%s%s", PRIVATE, suffix, PEM);
  } else {
    asprintf (&path, "%s%s%s", PUBLIC, suffix, PEM);
  }

  EC_KEY *key = get_ec_key(path, private_key);

  free(path);
  return key;
}

EC_KEY * get_key_from_secret(Bin* secret){

  // Hash secret
  Bin* hash = new Bin(HASH_256);
  SHA256(secret->data, secret->len, hash->data);

  // Init EC_KEY
  EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (eckey == NULL)
  {
      printf("get_key_from_secret: Failed to create new EC Key\n");
      return NULL;
  }

  BN_CTX *ctx = NULL;
  BIGNUM *private_key = NULL;

  // Create context
  if ((ctx = BN_CTX_new()) == NULL){
    return NULL;
  }
  BN_CTX_start(ctx);

  // Load private key
  private_key = BN_bin2bn(hash->data, hash->len, NULL);
  if(private_key == NULL){
    printf("get_key_from_secret: Failed to convert private key\n");
    return NULL;
  }

  // Derive public key
  const EC_GROUP *group = EC_KEY_get0_group(eckey);
  EC_POINT *public_key = EC_POINT_new(group);
  if(EC_POINT_mul(group, public_key, private_key, NULL, NULL, ctx) != 1){
    printf("get_key_from_secret: Failed to derive public key\n");
    return NULL;
  }

  if(EC_KEY_set_private_key(eckey, private_key) != 1){
    printf("get_key_from_secret: Failed to set privte key\n");
    return NULL;
  }

  if(EC_KEY_set_public_key(eckey, public_key) != 1){
    printf("get_key_from_secret: Failed to set public key\n");
    return NULL;
  }

  // Cleanup
  delete hash;
  BN_free(private_key);
  EC_POINT_free(public_key);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  return eckey;
}
//============================================================================

ECDSA_SIG* EC_sign(EC_KEY * eckey, Bin* hash)
{
    ECDSA_SIG *sig = NULL;

    sig = ECDSA_do_sign(hash->data, hash->len, eckey);
    if (sig == NULL)
    {
        printf("EC_sign: Failed to generate EC Signature\n");
    }

  return sig;
}

bool EC_verify (EC_KEY * eckey, Bin* hash, ECDSA_SIG* signature){
  bool ret = false;

  int status = ECDSA_do_verify(hash->data, hash->len, signature, eckey);
  if (status != 1)
  {
      printf("EC_verify: Failed to verify EC Signature\n");
  }
  else
  {
      ret = true;
  }

  return ret;
}

// Trnaslation of the python-bitcoinlib signature_to_low_s function
bool convert_sig_to_standard_der(ECDSA_SIG *sig, EC_KEY *key){

  const EC_GROUP * group = EC_KEY_get0_group(key);
  BIGNUM *order = BN_new();
  BIGNUM *half_order = BN_new();

  BN_CTX *ctx = BN_CTX_new();
  if (ctx == NULL) {
    printf("convert_sig_to_standard_der: Couldn't get new CTX\n");
    return false;
  }

  EC_GROUP_get_order(group, order, ctx);
  BN_rshift1(half_order, order);

  // Verify that s is over half the order of the curve before we actually subtract anything from it
  if (BN_cmp(sig->s, half_order) > 0){
    BN_sub(sig->s, order, sig->s);
  }

  BN_free(half_order);
  BN_free(order);
  BN_CTX_free(ctx);

  return true;
}

//============================================================================

bool serialize_ec_signature_der(ECDSA_SIG *sig, Bin* serial){

  int l;
  serial->len = i2d_ECDSA_SIG(sig, NULL);
  if (serial->len == 0){
    return false;
  }
  serial->data = (unsigned char *)tmalloc(serial->len);
  unsigned char *p;

  p = serial->data;
  l = i2d_ECDSA_SIG(sig, &p);
  if (l == 0 || l != serial->len){
    return false;
  }

  return true;
}

ECDSA_SIG *deserialize_ec_signature_der(Bin* serial){
  unsigned char *p;
  p = serial->data;

  ECDSA_SIG *sig =  d2i_ECDSA_SIG(NULL, (const unsigned char **)&p, serial->len);
  return sig;
}

bool serialize_ec_signature(ECDSA_SIG *sig, Bin* serial){

  serial->len = 32 * 2;
  serial->data = (unsigned char *)tmalloc(serial->len);

  BNToBin(sig->r, serial->data, 32);
  BNToBin(sig->s, serial->data + 32, 32);

  return true;
}

ECDSA_SIG *deserialize_ec_signature(Bin* serial){

  ECDSA_SIG* sig = ECDSA_SIG_new();

  BIGNUM *r = BN_new();
  BIGNUM *s = BN_new();

  if (BN_bin2bn(serial->data, 32, r) == NULL){
    printf("deserialize_ec_signature: Failed to convert r\n");
    return NULL;
  }

  if (BN_bin2bn(serial->data + 32, 32, s) == NULL){
    printf("deserialize_ec_signature: Failed to convert s\n");
    return NULL;
  }

  BN_copy(sig->r, r);
  BN_copy(sig->s, s);

  BN_free(r);
  BN_free(s);


  return sig;
}

//============================================================================

bool serialize_ec_publickey(EC_KEY *key, Bin* serial){

  serial->len = i2o_ECPublicKey(key, NULL);
  if (serial->len == 0){
    return false;
  }

  unsigned char *s = (unsigned char *)tmalloc(serial->len);
  unsigned char *s2 = s;

  if(i2o_ECPublicKey(key, &s2) != serial->len){
    tfree(s);
    serial->data = NULL;
    return false;
  }

  serial->data = s;
  return true;
}

EC_KEY* deserialize_ec_publickey(Bin* serial){
  // Group needs to be set to deserialize public key
  EC_KEY *temp = EC_KEY_new();
  EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(NID_secp256k1);
  EC_KEY_set_group(temp,ecgroup);

  unsigned char *p;
  p = serial->data;

  temp = o2i_ECPublicKey(&temp, (const unsigned char **)&p, serial->len);

  // Cleanup
  if (ecgroup != NULL){
    EC_GROUP_free(ecgroup);
  }

  return temp;
}

bool serialize_ec_privatekey(EC_KEY *key, Bin* serial){

  serial->len = i2d_ECPrivateKey(key, NULL);
  if (serial->len == 0){
    return false;
  }

  serial->data = (unsigned char *)tmalloc(serial->len);
  unsigned char *serial2 = serial->data;

  if(i2d_ECPrivateKey(key, &serial2) != serial->len){
    tfree(serial->data);
    serial->data = NULL;
    return false;
  }

  return true;
}

//============================================================================
