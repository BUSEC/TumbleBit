#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE alice_client
#include <boost/test/unit_test.hpp>

#include "alice_client.h"


BOOST_AUTO_TEST_CASE(client){

  bool status;

  // Setup RSA
  RSA * rsa = get_public_rsa(2048, (char *)"tumbler");
  BOOST_REQUIRE_MESSAGE(rsa != NULL, "test_alice_client: Failed load RSA key");
  int rsa_len = RSA_size(rsa);

  Bin* y_sk = new Bin();

  // Create epsilon
  Bin* epsilon = new Bin();
  Bin *y =  new Bin(rsa_len);
  epsilon->len = rsa_len;
  epsilon->data = get_random(rsa_len * 8, rsa->n);

  // Encrypt epsilon
  int s = RSA_public_encrypt(rsa_len, epsilon->data, y->data, rsa, RSA_NO_PADDING);
  BOOST_REQUIRE_MESSAGE(s != -1, "test_alice_client: Failed to create e^pk");

  status = get_decryption(y, y_sk);
  BOOST_REQUIRE_MESSAGE(status == true, "test_alice_client: Failed to get decryption");


  BOOST_REQUIRE_MESSAGE(*y_sk == *epsilon, "test_alice_client: Decryption is invalid!");
  printf("Success!\n");

  // Cleanup
  delete y;
  delete y_sk;
  delete epsilon;
  RSA_free(rsa);
}
