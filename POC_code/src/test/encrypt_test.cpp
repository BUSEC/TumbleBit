#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE encrypt_test

#include "encrypt.h"
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_CASE(test_encrypt_xor){

  bool status;

  Bin *message   = new Bin();
  Bin *key       = new Bin();
  Bin *cipher    = new Bin();
  Bin *decrypted = new Bin();

  key->len = 2048/8;
  key->data = get_random(2048);

  message->len = 64;
  message->data = get_random(512);

  // Encrypt
  status = encrypt(message, key, cipher);
  BOOST_REQUIRE_MESSAGE(status == true, "test_encrypt: Failed to encrypt message");
  BOOST_REQUIRE_MESSAGE(cipher != NULL, "test_encrypt: Cipher shouldn't be null");

  // Decrypt
  status = decrypt(cipher, key, decrypted);
  BOOST_REQUIRE_MESSAGE(status == true, "test_encrypt: Failed to decrypt message");


  // Verify
  BOOST_REQUIRE_MESSAGE(*message == *decrypted, "test_encrypt: Failed to decrypt message");

  // Cleanup
  delete message;
  delete key;
  delete cipher;
  delete decrypted;
}

BOOST_AUTO_TEST_CASE(test_encrypt_chacha){

  bool status;

  Bin *message   = NULL;
  Bin *key       = new Bin();
  Bin *cipher    = new Bin();
  Bin *decrypted = new Bin();

  int len = 5;
  message = new Bin(len);
  memcpy(message->data, "test1", len);

  // printf("Message is:\n");
  // message->print();

  // Encrypt
  status = encrypt_chacha(message, key, cipher);
  BOOST_REQUIRE_MESSAGE(status == true, "test_encrypt: Failed to encrypt message");
  BOOST_REQUIRE_MESSAGE(cipher != NULL, "test_encrypt: Cipher shouldn't be null");

  // printf("Cipher is %d:\n", cipher->len);
  // cipher->print();
  //
  // printf("Key is %d:\n", key->len);
  // key->print();

  // Decrypt
  status = decrypt_chacha(cipher, key, decrypted);
  BOOST_REQUIRE_MESSAGE(status == true, "test_encrypt: Failed to decrypt message");

  // printf("Plain_text is:\n");
  // decrypted->print();

  // Verify
  BOOST_REQUIRE_MESSAGE(*message == *decrypted, "test_encrypt: Failed to decrypt message");

  // Cleanup
  delete message;
  delete key;
  delete cipher;
  delete decrypted;
}

BOOST_AUTO_TEST_CASE(test_xor){

  int len = 12;
  int bits = len * 8;

  Bin* key = new Bin();
  Bin* enc = new Bin();
  Bin* dec = new Bin();
  Bin* message = new Bin(len);
  memcpy(message->data, "TESTMESSAGE", len);


  key->len = len;
  key->data = get_random(bits);

  enc->len = len;
  enc->data = XOR_enc_dec(message, key, len);

  dec->len = len;
  dec->data = XOR_enc_dec(enc, key, len);


  BOOST_REQUIRE_MESSAGE(*dec == *message, "test_xor_encrypt: Failed to decrypt message");

  // Cleanup
  delete key;
  delete enc;
  delete dec;
  delete message;
}
