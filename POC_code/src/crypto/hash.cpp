#include "hash.h"

Bin* full_domain_hash(RSA *rsa, Bin* msg, const EVP_MD *hash){
  if (!defined(msg) || hash == NULL || rsa == NULL){
    return NULL;
  }

  int mask_len = BN_num_bytes(rsa->n);
  unsigned char * mask = (unsigned char *) tmalloc(mask_len);
  mask[0] = 0;

  // Had a problem with sizeof(mask) - 1, since mask has changed to a pointer
  if (PKCS1_MGF1(mask + 1, mask_len - 1, msg->data, msg->len, hash) != 0) {
    printf("FDH failed.\n");
    return NULL;
  }

  Bin* h = new Bin();
  h->len = mask_len;
  h->data = mask;

  return h;
}

Bin* hash256(Bin* msg){
  Bin* hash = new Bin(HASH_256);
  Bin* temp_hash = new Bin(HASH_256);

  SHA256(msg->data, msg->len, temp_hash->data);
  SHA256(temp_hash->data, temp_hash->len, hash->data);

  delete temp_hash;

  return hash;
}

Bin* hmac256(Bin* msg, Bin* key){

  Bin* output = new Bin(32);

  if(HMAC(EVP_sha256(),key->data, key->len, msg->data, msg->len,
               output->data, NULL) == NULL){
                 return NULL;
  }

  return output;
}
