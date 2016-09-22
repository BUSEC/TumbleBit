#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE bin

#include "bin.h"
#include "utility.h"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_CASE(test_empty_constructor){

  Bin b = Bin();

  // Define
  int msg_len = 13;
  unsigned char *msg = (unsigned char *) malloc(msg_len - 1);

  memcpy(msg, "Test Message", msg_len - 1);

  b.data = msg;
  b.len = msg_len - 1;

  BOOST_REQUIRE_MESSAGE(memcmp(msg, b.data, b.len) == 0, "test_empty_constructor: Doesn't point to same memory");
}

BOOST_AUTO_TEST_CASE(test_int_constructor){

  // Define
  int msg_len = 13;
  Bin b = Bin(msg_len - 1);
  memcpy(b.data, "Test Message", b.len);


  BOOST_REQUIRE_MESSAGE(memcmp("Test Message", b.data, b.len) == 0, "test_int_constructor: Doesn't point to same memory");
}

BOOST_AUTO_TEST_CASE(test_full_constructor){

  // Define
  int msg_len = 13;
  unsigned char *msg = (unsigned char *) malloc(msg_len - 1);
  memcpy(msg, "Test Message", msg_len - 1);

  Bin b = Bin(msg_len - 1, msg);

  BOOST_REQUIRE_MESSAGE(memcmp(msg, b.data, b.len) == 0, "test_full_constructor: Doesn't point to same memory");
}

BOOST_AUTO_TEST_CASE(test_serialize){

  unsigned char expected[] = {0x0c, 0x00, 0x00, 0x00, 0x54, 0x65, 0x73, 0x74, 0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65};

  // Define
  int msg_len = 13;
  Bin b = Bin(msg_len - 1);
  memcpy(b.data, "Test Message", b.len);


  unsigned char *serial =  b.serialize();

  BOOST_REQUIRE_MESSAGE(memcmp(expected, serial, b.len + sizeof(int)) == 0, "test_serialize: Doesn't point to same memory");

  free(serial);
}

BOOST_AUTO_TEST_CASE(test_equality){

  Bin b = Bin();
  Bin b1 = Bin();
  Bin b2 = Bin();

  // Define
  int msg_len = 13;
  unsigned char *msg = (unsigned char *) malloc(msg_len - 1);
  unsigned char *msg1 = (unsigned char *) malloc(msg_len - 1);
  unsigned char *msg2 = (unsigned char *) malloc(msg_len - 1);

  memcpy(msg, "Test Message", msg_len - 1);
  memcpy(msg1, "Test Message", msg_len - 1);
  memcpy(msg2, "TEST MESSAGE", msg_len - 1);

  b.len = msg_len - 1;
  b.data = msg;

  b1.len = b.len;
  b1.data = msg1;

  b2.len = b.len;
  b2.data = msg2;


  BOOST_REQUIRE_MESSAGE( b == b1, "test_equality: b1 & b should be equal");
  BOOST_REQUIRE_MESSAGE( b != b2, "test_equality: b2 & b shouldn't be equal");
}
