#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE utility_test

#include <boost/test/unit_test.hpp>
#include "utility.h"

BOOST_AUTO_TEST_CASE(test_BNToBin){

  BN_CTX* ctx = BN_CTX_new();
  BN_CTX_start(ctx);
  BIGNUM* bn1 = BN_CTX_get(ctx);
  BIGNUM* bn2 = BN_CTX_get(ctx);
  BIGNUM* bn3 = BN_CTX_get(ctx);

  char *temp;

  BOOST_REQUIRE_MESSAGE(ctx != NULL , "test_BNToBin: Failed to setup context");
  BOOST_REQUIRE_MESSAGE(bn1 != NULL && bn2 != NULL && bn3 != NULL , "test_BNToBin: Failed to setup bignums");


  BN_zero(bn1);
  BN_ULONG longword = 0x0301FF00;
  BN_add_word(bn1, longword);

  //print_BN(bn1);

  int data_len = 256;
  unsigned char data1[data_len];
  unsigned char data2[data_len];

  memset(data1, 0xFF, data_len);
  memset(data2, 0xFF, data_len);

  int data1_len = BNToBin(bn1, data1, data_len);
  int data2_len = BN_bn2bin(bn1, data2);

  if (data1_len != data_len){
    printf("Unexpected write BNToBin length actual: %d expected: %d \n", data1_len, data_len);
  }
  BOOST_CHECK(data1_len == data_len);

  int bn1_len = BN_num_bytes(bn1);
  if (data2_len != bn1_len){
    printf("Unexpected write BN_bn2bin length actual: %d expected: %d \n", data2_len, bn1_len);
  }
  BOOST_CHECK(data2_len == bn1_len);


  BN_bin2bn(data2, data_len, bn2);
  temp = BN_bn2hex(bn2);
  char* expected_bn2_str = (char*) "0301FF00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
  BOOST_CHECK_MESSAGE(memcmp(temp, expected_bn2_str, data_len) == 0 , "test_BNToBin: BN_bin2bn produced an unexpected input");
  free(temp);

  BN_bin2bn(data1, data_len, bn3);
  temp = BN_bn2hex(bn3);
  char* expected_bn3_str = (char*) "0301FF00";
  BOOST_CHECK_MESSAGE(memcmp(temp, expected_bn3_str, bn1_len) == 0 , "test_BNToBin: BNToBin serialization failure");
  free(temp);

  // Cleanup
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

}
