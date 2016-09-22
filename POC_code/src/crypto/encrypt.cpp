#include "encrypt.h"

//============================================================================
//====== XOR Functions
//============================================================================

bool encrypt(Bin* plain_text, Bin *key, Bin* cipher_text){

  if (!defined(plain_text) || !defined(key) ||
      plain_text->len != 64 || cipher_text == NULL){
    return false;
  }

  // Hash
  Bin *temp_h = new Bin(HASH_512);
  SHA512(key->data, key->len, temp_h->data);

  // Decrypt
  cipher_text->len = plain_text->len;
  cipher_text->data = XOR_enc_dec(plain_text, temp_h, plain_text->len);

  delete temp_h;

  return true;
}

bool decrypt(Bin* cipher_text, Bin *key, Bin* plain_text){

  if (!defined(key) || !defined(cipher_text) ||
      cipher_text->len != 64 || plain_text == NULL){
    return false;
  }

  // Hash
  Bin *temp_h = new Bin(HASH_512);
  SHA512(key->data, key->len, temp_h->data);

  // Decrypt
  plain_text->len = cipher_text->len;
  plain_text->data = XOR_enc_dec(cipher_text, temp_h, cipher_text->len);

  delete temp_h;

  return true;
}

unsigned char * XOR_enc_dec(Bin* m, Bin* k, int len){
  if (m->len != k->len){
    return NULL;
  }

  unsigned char * result = (unsigned char *) tmalloc(len * sizeof(unsigned char));
  for (int i = 0; i < len; i++){
    result[i] = m->data[i] ^ k->data[i];
  }
  return result;
}

//============================================================================
//====== CHACHA  Functions
//============================================================================

bool encrypt_chacha(Bin* plain_text, Bin *key, Bin* cipher_text){

  if (!defined(plain_text) || key == NULL || plain_text == NULL){
    return false;
  }

  key->len = KEY_LEN;
  key->data = get_random(KEY_LEN * 8);

  Bin iv = Bin();
  iv.len = 8;
  iv.data  = get_random(8*8);

  Bin cipher = Bin(plain_text->len);

  // Encrypt
  chacha(&cipher, plain_text, key, &iv);

  cipher_text->len  = plain_text->len + 8;
  cipher_text->data = (unsigned char *) malloc(cipher_text->len);
  memcpy(cipher_text->data, iv.data, 8);
  memcpy(cipher_text->data + 8, cipher.data, plain_text->len);

  return true;
}

bool decrypt_chacha(Bin* cipher_text, Bin *key, Bin* plain_text){

  if (!defined(key) || !defined(cipher_text) || plain_text == NULL){
    return false;
  }

  Bin iv =  Bin(8);
  Bin cipher = Bin(cipher_text->len - 8);

  memcpy(iv.data, cipher_text->data, 8);
  memcpy(cipher.data, cipher_text->data + 8, cipher.len);


  // Decrypt sig
  plain_text->len = cipher.len;
  plain_text->data = (unsigned char *) tmalloc(cipher.len);
  chacha(plain_text, &cipher, key, &iv);

  return true;
}

bool chacha(Bin* out, Bin* in, Bin* key, Bin* iv){
  if (out == NULL || !defined(in) || !defined(key) || key->len != 16 || !defined(iv)){
    return false;
  }

  ChaCha_ctx ctx;

  ChaCha_set_key(&ctx, key->data, 128);
  ChaCha_set_iv(&ctx, iv->data, NULL);
  ChaCha(&ctx, out->data, in->data, in->len);

  return true;
}
