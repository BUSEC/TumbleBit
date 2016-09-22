#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE EC_Test

#include "ec.h"
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_CASE(test_key_generation){

  bool status;

  // Generate new ec key
  const char *suffix = "test";
  status = generate_EC_key(suffix, suffix);

  BOOST_REQUIRE_MESSAGE(status == true, "test_key_generation: Failed to generate EC key");

  // Try to read key
  EC_KEY *key = get_ec_key_by_suffix(suffix, true);

  BOOST_REQUIRE_MESSAGE(key != NULL, "test_key_generation: Failed to get private EC key");

  EC_KEY_free(key);
}

BOOST_AUTO_TEST_CASE(test_sign_verify)
{
  // Get private key
  const char *suffix = "test";
  EC_KEY * key = get_ec_key_by_suffix(suffix, true);

  BOOST_REQUIRE_MESSAGE(key != NULL, "test_sign_verify: Failed to get private EC key");

  // Sign
  Bin hash = Bin(32);
  memcpy(hash.data, "c7fbca202a95a570285e3d700eb04ca2", hash.len);

  ECDSA_SIG * signature =  EC_sign(key, &hash);

  BOOST_REQUIRE_MESSAGE(signature != NULL, "test_sign_verify: Failed to sign message");

  // Cleanup
  EC_KEY_free(key);

  // Get key
  key = get_ec_key_by_suffix(suffix, false);

  BOOST_REQUIRE_MESSAGE(key != NULL, "test_sign_verify: Failed get public EC key");

  // Verify
  bool s =  EC_verify(key, &hash, signature);

  BOOST_REQUIRE_MESSAGE(s == true, "test_sign_verify: Failed to verify signature");

  // Serialize + deserialize
  Bin serial = Bin();

  s = serialize_ec_signature(signature, &serial);
  BOOST_REQUIRE_MESSAGE(s == true, "test_sign_verify: Failed serialize signature");

  // printf("serial signature is:\n");
  // serial.print();

  ECDSA_SIG *sig2;
  sig2 = deserialize_ec_signature(&serial);
  BOOST_REQUIRE_MESSAGE(sig2 != NULL, "test_sign_verify: Failed to deserialize signature");

  // Verify
  s =  EC_verify(key, &hash, sig2);

  BOOST_REQUIRE_MESSAGE(s == true, "test_sign_verify: Failed to verify signature after serialization");

  // Cleanup
  ECDSA_SIG_free(signature);
  ECDSA_SIG_free(sig2);
  EC_KEY_free(key);

}

BOOST_AUTO_TEST_CASE(test_sig_convert)
{
  // Get private key
  const char *suffix = "test";
  EC_KEY * key = get_ec_key_by_suffix(suffix, true);

  BOOST_REQUIRE_MESSAGE(key != NULL, "test_sign_verify: Failed to get private EC key");

  // Sign
  Bin hash = Bin(32);
  memcpy(hash.data, "c7fbca202a95a570285e3d700eb04ca2", hash.len);

  // printf("Hash is:\n");
  // hash.print();

  ECDSA_SIG * signature =  EC_sign(key, &hash);

  BOOST_REQUIRE_MESSAGE(signature != NULL, "test_sign_verify: Failed to sign message");

  // Convert sig to standard format
  convert_sig_to_standard_der(signature, key);


  // Cleanup
  EC_KEY_free(key);

  // Get key
  key = get_ec_key_by_suffix(suffix, false);

  BOOST_REQUIRE_MESSAGE(key != NULL, "test_sign_verify: Failed get public EC key");

  // Verify
  bool s =  EC_verify(key, &hash, signature);

  BOOST_REQUIRE_MESSAGE(s == true, "test_sign_verify: Failed to verify signature");

  // Cleanup
  ECDSA_SIG_free(signature);
  EC_KEY_free(key);

}


BOOST_AUTO_TEST_CASE(test_sig_serialize)
{
  // Get private key
  const char *suffix = "test";
  EC_KEY * key = get_ec_key_by_suffix(suffix, true);

  BOOST_REQUIRE_MESSAGE(key != NULL, "test_sig_serialize: Failed to get private EC key");

  // Sign
  Bin hash = Bin(32);
  memcpy(hash.data, "c7fbca202a95a570285e3d700eb04ca2", hash.len);

  // printf("Hash is:\n");
  // hash.print();

  ECDSA_SIG * signature =  EC_sign(key, &hash);

  BOOST_REQUIRE_MESSAGE(signature != NULL, "test_sig_serialize: Failed to sign message");

  // Cleanup
  EC_KEY_free(key);

  // Get key
  key = get_ec_key_by_suffix(suffix, false);

  BOOST_REQUIRE_MESSAGE(key != NULL, "test_sig_serialize: Failed get public EC key");

  // Verify
  bool s =  EC_verify(key, &hash, signature);

  BOOST_REQUIRE_MESSAGE(s == true, "test_sig_serialize: Failed to verify signature");

  // Serialize + deserialize
  Bin serial = Bin();

  s = serialize_ec_signature(signature,& serial);
  BOOST_REQUIRE_MESSAGE(s == true, "test_sig_serialize: Failed serialize signature");

  ECDSA_SIG *sig2;
  sig2 = deserialize_ec_signature(&serial);
  BOOST_REQUIRE_MESSAGE(sig2 != NULL, "test_sig_serialize: Failed to deserialize signature");

  // Verify
  s =  EC_verify(key, &hash, sig2);

  BOOST_REQUIRE_MESSAGE(s == true, "test_sig_serialize: Failed to verify signature after serialization");

  // Cleanup
  ECDSA_SIG_free(signature);
  ECDSA_SIG_free(sig2);
  EC_KEY_free(key);
}

BOOST_AUTO_TEST_CASE(test_no_nonce_reuse)
{

   const char *suffix = "test";
  EC_KEY * key = get_ec_key_by_suffix(suffix, true);

  // Sign
  Bin hash1 = Bin(32);
  memcpy(hash1.data, "19ebca000095a201285e3d7002204edf", hash1.len);

  Bin hash2 = Bin(32);
  memcpy(hash2.data, "19ebca000095a201285e3d7002204edf", hash2.len);

  ECDSA_SIG * signature1 =  EC_sign(key, &hash1);
  ECDSA_SIG * signature2 =  EC_sign(key, &hash2);

  Bin serial1 = Bin();
  Bin serial2 = Bin();

  serialize_ec_signature(signature1, &serial1);
  serialize_ec_signature(signature2, &serial2);

  BOOST_CHECK_MESSAGE(memcmp(serial1.data, serial2.data, 32)!=0, "ECDSA nonces should not be the same");


  // Cleanup
  ECDSA_SIG_free(signature1);
  ECDSA_SIG_free(signature2);
  EC_KEY_free(key);
}

BOOST_AUTO_TEST_CASE(test_key_from_secret)
{

  Bin* secret = new Bin(20);
  memcpy(secret->data, "TumbleBit_4241304455", secret->len);
  EC_KEY * key = get_key_from_secret(secret);

  Bin* pubkey = new Bin();
  bool status = serialize_ec_publickey(key, pubkey);
  BOOST_CHECK_MESSAGE(status, "test_key_from_secret: Failed to serialize public key");


  char* pubkey_str = get_hex_str(pubkey);
  char* expected = (char *) "046ee5d82c7fece37c8f98f36bc619d2484e643ac10cb59df4ae9d4ae76816105ce2c85f960ad2726e058be242bc3b94e12c8ad033b9432ccb98fa61433557d933";


  BOOST_CHECK_MESSAGE(strcmp(pubkey_str, expected) == 0, "test_key_from_secret: Public keys don't match");

  delete pubkey;
  delete secret;
  free(pubkey_str);
  EC_KEY_free(key);
}
