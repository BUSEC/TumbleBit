#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE blind_rsa_test

#include "blind_rsa.h"
#include "random.h"
#include "hash.h"

#include <boost/test/unit_test.hpp>
#include <openssl/err.h>

BOOST_AUTO_TEST_CASE(test_blind){
    //============================================================================
    //====== Setup RSA + Blinding
    //============================================================================
    RSA *rsa = NULL;
    bool status;

    rsa = get_private_rsa(2048, (char *)"test");

    BN_BLINDING *blinding = NULL;
    blinding = setup_blinding(rsa);

    BOOST_REQUIRE_MESSAGE(blinding != NULL, "test_blind: Failed to setup blinding");

    //============================================================================
    //====== Hash message
    //============================================================================
    int msg_len = 13;
    unsigned char *msg2 = (unsigned char *) malloc(msg_len);

    memcpy(msg2, "Test Message", msg_len);

    Bin msg = Bin(msg_len, msg2);

    // Hash
    Bin *hash = full_domain_hash(rsa, &msg, EVP_sha512());

    //============================================================================
    //====== Blind then Sign
    //============================================================================

    Bin blinded_hash = Bin(BN_num_bytes(rsa->n));

    status = blind(blinding, hash, &blinded_hash);

    BOOST_REQUIRE_MESSAGE(status == true, "test_blind: Failed to blind message");

    int sig_len = RSA_size(rsa);

    Bin blind_sig = Bin(sig_len);
    Bin sig = Bin(sig_len);

    // Sign
    sign(rsa, &blinded_hash, &blind_sig);


    //============================================================================
    //====== Unblind then Verify
    //============================================================================

    // Unblind sig
    unblind(blinding, &blind_sig, &sig);

    // Verify
    status = verify(rsa, hash, &sig);

    BOOST_REQUIRE_MESSAGE(status == true, "test_blind: Failed to blind message");

    // Cleanup
    delete hash;
    RSA_free(rsa);
    BN_BLINDING_free(blinding);
}

BOOST_AUTO_TEST_CASE(test_double_blind){
  //============================================================================
  //====== Setup RSA + Blinding
  //============================================================================
  RSA *rsa = NULL;
  bool status;

  rsa = get_private_rsa(2048, (char *)"test");
  BOOST_REQUIRE_MESSAGE(rsa != NULL, "test_double_blind: Failed load RSA key");

  // Setup blinding
  BN_BLINDING *blinding = NULL;
  BN_BLINDING *b2 = NULL;
  BN_BLINDING *b3 = NULL;
  blinding = setup_blinding(rsa);
  b2 = setup_blinding(rsa);
  b3 = setup_blinding(rsa);

  BOOST_REQUIRE_MESSAGE(blinding != NULL && b2 != NULL && b3 != NULL, "test_double_blind: Failed to setup blinding");

  //============================================================================
  //====== Hash message
  //============================================================================
  const char *msg2 = "Alice was beginning to get very tired of sitting by her sister on the bank, and of having nothing to do: once or twice she had peeped into the book her sister was reading, but it had no pictures or conversations in it, 'and what is the use of a book,' thought Alice 'without pictures or conversations?'";
  int msg_len = strlen(msg2);

  Bin msg = Bin(msg_len - 1);
  memcpy(msg.data, msg2, msg.len);


  // Hash
  int hash_len = BN_num_bytes(rsa->n);
  Bin* hash = full_domain_hash(rsa, &msg, EVP_sha512());

  //============================================================================
  //====== Blind then Sign
  //============================================================================


  // Blind message
  Bin blinded_hash = Bin(hash_len);

  status = blind(blinding, hash, &blinded_hash);
  BOOST_REQUIRE_MESSAGE(status == true, "test_double_blind: Failed to blind b1");


  //============================================================================
  //====== TEST
  //============================================================================


  // Blind  with b2
  Bin b2_str = Bin(hash_len);

  status = blind(b2, &blinded_hash, &b2_str);
  BOOST_REQUIRE_MESSAGE(status == true, "test_double_blind: Failed to blind b2");

  // Blind  with b3
  Bin b3_str = Bin(hash_len);

  status = blind(b3, &blinded_hash, &b3_str);
  BOOST_REQUIRE_MESSAGE(status == true, "test_double_blind: Failed to blind b3");

  int sig_len = RSA_size(rsa);
  Bin sig_2 = Bin(sig_len);
  Bin sig_3 = Bin(sig_len);
  Bin blind_sig_2 = Bin(sig_len);
  Bin blind_sig_3 = Bin(sig_len);

  // Sign
  sign(rsa, &b2_str, &blind_sig_2);
  sign(rsa, &b3_str, &blind_sig_3);

  // Verify signatures
  status = verify(rsa, &b2_str, &blind_sig_2);
  BOOST_REQUIRE_MESSAGE(status == true, "test_double_blind: Failed to verify signature for b2_str");

  status = verify(rsa, &b3_str, &blind_sig_3);
  BOOST_REQUIRE_MESSAGE(status == true, "test_double_blind: Failed to verify signature for b3_str");

  //============================================================================
  //====== Unblind then Verify
  //============================================================================

  // Unblind 2
  Bin b2_u = Bin(sig_len);
  unblind(b2, &blind_sig_2, &b2_u);

  status = verify(rsa, &blinded_hash, &b2_u);
  BOOST_REQUIRE_MESSAGE(status == true, "test_double_blind: Failed to verify signature for blinded_hash_str from b2");

  // Unblind 3
  Bin b3_u = Bin(sig_len);
  unblind(b3, &blind_sig_3, &b3_u);

  status = verify(rsa, &blinded_hash, &b3_u);
  BOOST_REQUIRE_MESSAGE(status == true, "test_double_blind: Failed to verify signature for blinded_hash_str from b3");

  // Compare
  BOOST_REQUIRE_MESSAGE(b2_u == b3_u, "test_double_blind: Unblinded b2 & b3 messages are NOT the same");

  // Unblind 2 completly
  unblind(blinding, &b2_u, &sig_2);

  // Verify
  status = verify(rsa, hash, &sig_2);
  BOOST_REQUIRE_MESSAGE(status == true, "test_double_blind: Failed to blind message");

  // Unblind sig
  unblind(blinding, &b3_u, &sig_3);

  // Verify
  status = verify(rsa, hash, &sig_3);
  BOOST_REQUIRE_MESSAGE(status == true, "test_double_blind: Failed to verify unblind message");

  // Cleanup
  delete hash;
  RSA_free(rsa);
  BN_BLINDING_free(blinding);
  BN_BLINDING_free(b2);
  BN_BLINDING_free(b3);
}


BOOST_AUTO_TEST_CASE(test_EncBlindDecUnblind){

  RSA *rsa = NULL;
  bool status;

  rsa = get_private_rsa(2048, (char *)"test");
  BOOST_REQUIRE_MESSAGE(rsa != NULL, "test_EncBlindDecUnblind: Failed load RSA key");

  int sig_len = RSA_size(rsa);
  BN_BLINDING *blinding = setup_blinding(rsa);

  // Encrypted message
  unsigned char m[] = {0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50, 0x81,
                       0x90, 0x7c, 0xca, 0x0d, 0x22, 0xd8, 0xf8, 0xd2,
                       0x78, 0x4a, 0xbc, 0x0c, 0xad, 0x4d, 0x4f, 0xaf,
                       0x2c, 0x7a, 0xfa, 0x39, 0x97, 0xc6, 0x52, 0x0e,
                       0x3c, 0x50, 0xbc, 0x1a, 0x59, 0xc5, 0x1a, 0xf9,
                       0xff, 0xe9, 0xe7, 0x55, 0x27, 0x33, 0x02, 0xdc,
                       0x8c, 0x24, 0x0d, 0x45, 0x8a, 0xd7, 0xa9, 0xdd,
                       0xd3, 0x79, 0x38, 0x83, 0x80, 0xe3, 0x02, 0xd9,
                       0x6d, 0x48, 0x02, 0xe7, 0x88, 0x3d, 0xf6, 0xa1,
                       0xa5, 0x2d, 0xb8, 0x44, 0x08, 0x17, 0xe1, 0x38,
                       0x32, 0x36, 0x15, 0x7e, 0x27, 0xfa, 0xbc, 0x5c,
                       0xf1, 0x8c, 0x51, 0x3c, 0x2a, 0xf8, 0x78, 0x7e,
                       0x83, 0xc3, 0x50, 0x37, 0x3e, 0x44, 0x1b, 0xd6,
                       0xac, 0x9f, 0x68, 0xa0, 0x5d, 0xb8, 0xd5, 0xbb,
                       0x06, 0xc2, 0x4c, 0x0e, 0x07, 0xbe, 0x05, 0x39,
                       0xc5, 0x2b, 0x5a, 0x16, 0x0e, 0x6f, 0x05, 0xbd,
                       0x6e, 0x7f, 0xcc, 0xa4, 0xf8, 0xd5, 0xae, 0x74,
                       0x1a, 0x85, 0x55, 0xec, 0xf5, 0x10, 0x83, 0x4e,
                       0xe4, 0xff, 0xd7, 0xc2, 0xca, 0x7e, 0x61, 0xa3,
                       0xdb, 0xda, 0xdc, 0xfc, 0xe2, 0x74, 0x23, 0x0d,
                       0x8a, 0x35, 0x49, 0xd1, 0xb3, 0x0b, 0xc3, 0x60,
                       0xb2, 0x96, 0x42, 0x19, 0xd4, 0x93, 0x2e, 0x65,
                       0x7c, 0x7b, 0xfe, 0x35, 0x05, 0x66, 0x6c, 0x0c,
                       0x9f, 0x55, 0x36, 0xbe, 0xf0, 0xed, 0x54, 0x65,
                       0x11, 0xd9, 0x2a, 0x12, 0x3f, 0xea, 0x91, 0xe5,
                       0xb8, 0x48, 0xb8, 0x6c, 0x1e, 0x5c, 0x7b, 0x14,
                       0xea, 0xb9, 0x29, 0xe5, 0x1c, 0x46, 0xb9, 0xeb,
                       0x9d, 0xba, 0x98, 0x35, 0x37, 0xee, 0x6f, 0x2a,
                       0x83, 0xf5, 0xfa, 0xe7, 0x9f, 0x36, 0x90, 0xfe,
                       0x64, 0xf1, 0x29, 0xcd, 0x82, 0x58, 0xcd, 0xd3,
                       0x58, 0x9b, 0x2b, 0xdd, 0xbf, 0x5a, 0x61, 0x60,
                       0x10, 0x54, 0x3e, 0x23, 0x23, 0x17, 0x17, 0x17};

  Bin* enc_m = new Bin(sig_len);
  int r = RSA_public_decrypt(sig_len, (unsigned char*)m, enc_m->data, rsa, RSA_NO_PADDING);

  BOOST_REQUIRE_MESSAGE(r == sig_len, "test_EncBlindDecUnblind: Failed to decrypt");

  Bin* b_enc_m = new Bin(sig_len);
  blind(blinding, enc_m, b_enc_m);

  Bin* b_dec_m = new Bin(sig_len);
  status = sign(rsa, b_enc_m, b_dec_m);

  BOOST_REQUIRE_MESSAGE(status == true, "test_EncBlindDecUnblind: Sign failed");

  Bin* u_dec_m = new Bin(sig_len);
  unblind(blinding, b_dec_m, u_dec_m);

  Bin* dec_m = new Bin(sig_len);
  status = sign(rsa, enc_m, dec_m);

  BOOST_REQUIRE_MESSAGE(status == true, "test_EncBlindDecUnblind: Sign failed");
  BOOST_REQUIRE_MESSAGE(memcmp(m, dec_m->data, sig_len) == 0, "test_EncBlindDecUnblind: Should be the same");

  // Cleanup
  RSA_free(rsa);
  BN_BLINDING_free(blinding);
  delete dec_m;
  delete u_dec_m;
  delete b_dec_m;
  delete b_enc_m;
  delete enc_m;
}

BOOST_AUTO_TEST_CASE(test_blinding_with_r){

  bool status;
  // Setup RSA
  RSA * rsa = get_private_rsa(2048, (char *)"test");
  BOOST_REQUIRE_MESSAGE(rsa != NULL, "test_blinding_with_r: Failed load RSA key");
  int len = RSA_size(rsa);

  // Get random r
  Bin r  = Bin();
  r.len  = len;
  r.data = get_random(len * 8, rsa->n);

  // Get blinding
  BN_BLINDING * blinding = setup_blinding(rsa, &r);
  BOOST_REQUIRE_MESSAGE(blinding != NULL, "test_blinding_with_r: Failed setup blinding");

  // Setup message
  int msg_len = 13;
  unsigned char *msg2 = (unsigned char *) malloc(msg_len);

  memcpy(msg2, "Test Message", msg_len);

  Bin msg = Bin(msg_len, msg2);

  // Hash
  Bin* hash = full_domain_hash(rsa, &msg, EVP_sha512());

  // Blind
  Bin blinded_hash = Bin(len);
  status = blind(blinding, hash, &blinded_hash);
  BOOST_REQUIRE_MESSAGE(status == true, "test_blinding_with_r: Failed blind message");

  // Sign
  Bin sig = Bin(len);
  status = sign(rsa, &blinded_hash, &sig);
  BOOST_REQUIRE_MESSAGE(status == true, "test_blinding_with_r: Failed sign message");

  // Unblind
  Bin unblinded = Bin(len);
  status = unblind(blinding, &sig, &unblinded);
  BOOST_REQUIRE_MESSAGE(status == true, "test_blinding_with_r: Failed blind message");

  // Verify
  status = verify(rsa, hash, &unblinded);
  BOOST_REQUIRE_MESSAGE(status == true, "test_blinding_with_r: Failed to verify unblind message");

  // Cleanup
  delete hash;
  RSA_free(rsa);
  BN_BLINDING_free(blinding);
}

BOOST_AUTO_TEST_CASE(test_comparison_and_revert){
  // Setup RSA
  RSA * rsa = get_private_rsa(2048, (char *)"test");
  BOOST_REQUIRE_MESSAGE(rsa != NULL, "test_comparison_and_revert: Failed load RSA key");
  int len = RSA_size(rsa);

  // Get random r
  Bin r  = Bin();
  r.len  = len;
  r.data = get_random(len * 8, rsa->n);

  // Get blinding
  BN_BLINDING * blinding = setup_blinding(rsa, &r);
  BOOST_REQUIRE_MESSAGE(blinding != NULL, "test_comparison_and_revert: Failed setup blinding");

  //============================================================================
  //====== Compare r^pk to A
  //============================================================================
  Bin rpk = Bin(len);

  int s = RSA_public_encrypt(len, r.data, rpk.data, rsa, RSA_NO_PADDING);
  BOOST_REQUIRE_MESSAGE(s != -1, "test_comparison_and_revert: Failed encrypt r");

  //Convert A
  Bin A = Bin(len);
  BNToBin(blinding->A, A.data, len);

  BOOST_REQUIRE_MESSAGE(A == rpk, "test_comparison_and_revert: rpk != A");

  //============================================================================
  //====== Revert blinded message
  //============================================================================
  bool status;

  // Setup message
  int msg_len = 13;
  unsigned char *msg2 = (unsigned char *) malloc(msg_len);

  memcpy(msg2, "Test Message", msg_len);

  Bin msg = Bin(msg_len, msg2);

  // Hash
  Bin* hash = full_domain_hash(rsa, &msg, EVP_sha512());

  // Blind
  Bin blinded_hash = Bin(len);
  status = blind(blinding, hash, &blinded_hash);
  BOOST_REQUIRE_MESSAGE(status == true, "test_comparison_and_revert: Failed blind message");

  // Revert
  Bin unblinded_hash = Bin(len);
  status = revert_blind(rsa, &blinded_hash, &A, &unblinded_hash);
  BOOST_REQUIRE_MESSAGE(status == true, "test_comparison_and_revert: Failed to revert blind");

  BOOST_REQUIRE_MESSAGE(unblinded_hash == *hash, "test_comparison_and_revert: Reverted hash != hash");


  // Cleanup
  delete hash;
  RSA_free(rsa);
  BN_BLINDING_free(blinding);
}
