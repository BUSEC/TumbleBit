#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE scc

#include <boost/test/unit_test.hpp>
#include "hash.h"
#include "scc.h"

#include <openssl/sha.h>

int myrandom (int i) { return rand()%i;}

BOOST_AUTO_TEST_CASE(test_find_indices){

  int len = 5;

  Bin* temp;

  std::vector<Bin*> v1;
  std::vector<Bin*> v2;
  std::vector<Bin*> v3;

  // Vector 1
  temp = new Bin(len);
  memcpy(temp->data, "test1", len);
  v1.push_back(temp);

  temp = new Bin(len);
  memcpy(temp->data, "test2", len);
  v1.push_back(temp);

  temp = new Bin(len);
  memcpy(temp->data, "test3", len);
  v1.push_back(temp);

  // Vector 2
  temp = new Bin(len);
  memcpy(temp->data, "test4", len);
  v2.push_back(temp);

  temp = new Bin(len);
  memcpy(temp->data, "test5", len);
  v2.push_back(temp);

  temp = new Bin(len);
  memcpy(temp->data, "test6", len);
  v2.push_back(temp);


  // Combine v1 & v2
  v3.insert(v3.end(), v1.begin(), v1.end());
  v3.insert(v3.end(), v2.begin(), v2.end());

  // Permute
  random_shuffle(v3.begin(),v3.end(), myrandom);


  std::vector<int> i1;
  std::vector<int> i2;
  int j = 0;

  find_indices(v3, v1, i1);
  find_indices(v3, v2, i2);

  for (unsigned int i = 0; i < v1.size(); i++){
    j = i1[i];
    BOOST_REQUIRE_MESSAGE(memcmp(v1[i]->data, v3[j]->data, len) == 0, "test_find_indices: Indices don't match");
  }

  for (unsigned int i = 0; i < v2.size(); i++){
    j = i2[i];
    BOOST_REQUIRE_MESSAGE(memcmp(v2[i]->data, v3[j]->data, len) == 0, "test_find_indices: Indices don't match");
  }

  free_Bins(v1);
  free_Bins(v2);
}


BOOST_AUTO_TEST_CASE(test_blind_vectors){

  Bin* message;
  Bin* hash;
  int len = 5;
  bool status;

  std::vector<Bin*> blinded;
  std::vector<Bin*> sigs;
  std::vector<Bin*> unblinded;
  std::vector<BN_BLINDING *> blinds;

  // Setup RSA
  RSA * rsa = get_private_rsa(2048, (char *)"test");
  BOOST_REQUIRE_MESSAGE(rsa != NULL, "test_blind_vectors: Failed load RSA key");

  // Setup vector
  message = new Bin(len);
  memcpy(message->data, "test1", len);

  // Hash message
  int rsa_len = RSA_size(rsa);
  hash =  full_domain_hash(rsa, message, EVP_sha512());
  BOOST_REQUIRE_MESSAGE(hash->data != NULL, "test_blind_vectors: Failed to hash message");


  // Setup blinds
  status = create_blinds(rsa, 3, blinds);
  BOOST_REQUIRE_MESSAGE(status == true, "test_blind_vectors: Failed to create blinds");

  // Apply blinds
  status = apply_blinds(hash, blinds, blinded);
  BOOST_REQUIRE_MESSAGE(status == true, "test_blind_vectors: Failed to apply blinds");


  // Sign blinded messages
  Bin* temp;
  for(unsigned int i=0; i < blinds.size(); i++){
    temp = new Bin(rsa_len);
    status = sign(rsa, blinded.at(i), temp);
    BOOST_REQUIRE_MESSAGE(status == true, "test_blind_vectors: Failed to sign blinds");
    sigs.push_back(temp);
  }

  // Remove blinds
  status = remove_blinds(sigs, rsa_len, blinds, unblinded);
  BOOST_REQUIRE_MESSAGE(status == true, "test_blind_vectors: Failed to remove blinds");

  // Verify unblinded message
  for(unsigned int i=0; i < unblinded.size(); i++){
    BOOST_REQUIRE_MESSAGE(memcmp(unblinded.at(i)->data, hash->data, len) == true, "test_blind_vectors: Unblinded != message");
  }

  // Cleanup
  delete message;
  delete hash;
  free_Bins(unblinded);
  free_Bins(blinded);
  free_Bins(sigs);
  free_blinds(blinds);
  RSA_free(rsa);

}

BOOST_AUTO_TEST_CASE(test_key_deserialization){

  // Setup
  bool status;
  int n_keys = 15;
  int key_len = 32; // 256 bits
  Bin *serial_keys = new Bin(key_len * n_keys);

  std::vector<Bin*> keys;
  std::vector<Bin*> expected_keys;

  // Expected keys
  char *temp_str = NULL;
  Bin *temp_h = NULL;
  for(int i=1; i <= n_keys; i++){

    // Create
    asprintf (&temp_str, "test%d", i);

    // Hash
    temp_h = new Bin(SHA256_DIGEST_LENGTH);
    SHA256((unsigned char *)temp_str, strlen(temp_str), temp_h->data);

    // Add
    expected_keys.push_back(temp_h);

    free(temp_str);
  }

  // Get key from file
  FILE *file;
  file = fopen("./keys/keys.bin","rb");
  fread(serial_keys->data, serial_keys->len, 1, file);
  fclose(file);

  // Deserialize
  status = deserialize_vector(serial_keys, keys, n_keys, key_len);
  BOOST_REQUIRE_MESSAGE(status == true, "test_key_deserialization: Failed to deserialize keys");

  // Check
  for(int i=0; i < n_keys; i++){
    status = (*expected_keys.at(i) == *keys.at(i));
    BOOST_REQUIRE_MESSAGE(status == true, "test_key_deserialization: key doesn't match expected key");
  }

  // Cleanup
  delete serial_keys;
  free_Bins(expected_keys);
  free_Bins(keys);

}

BOOST_AUTO_TEST_CASE(test_serialization){

  int n = 10;
  int len = 5;
  bool status;

  std::vector<Bin*> vec;
  std::vector<Bin*> vec_d;
  Bin *serial = new Bin();

  // Setup vector
  char *temp_str = NULL;
  Bin *temp_bin = NULL;
  for (int i = 0; i < n; i++){

    asprintf (&temp_str, "test%d", i);
    temp_bin = new Bin(len, (unsigned char *) temp_str);

    vec.push_back(temp_bin);
  }

  // Serialize
  status = serialize_vector(serial, vec, n, len);
  BOOST_REQUIRE_MESSAGE(status == true, "test_serialization: Failed to serialize vector");

  // Deserialize
  status = deserialize_vector(serial, vec_d, n, len);
  BOOST_REQUIRE_MESSAGE(status == true, "test_serialization: Failed to deserialize vector");

  // Compare vectors
  for (int i = 0; i < n; i++){
    BOOST_REQUIRE_MESSAGE(*vec.at(i) == *vec_d.at(i), "test_serialization: vectors don't match");
  }


  // Cleanup
  delete serial;
  free_Bins(vec);
  free_Bins(vec_d);
}

BOOST_AUTO_TEST_CASE(test_int_serialization){

  int n = 10;
  bool status;

  std::vector<int> vec;
  std::vector<int> vec_d;
  Bin *serial = new Bin();

  // Setup vector
  for (int i = 0; i < n; i++){
    vec.push_back(i);
  }

  // Serialize
  status = serialize_int_vector(serial, vec, n);
  BOOST_REQUIRE_MESSAGE(status == true, "test_int_serialization: Failed to serialize vector");

  // Deserialize
  status = deserialize_int_vector(serial, vec_d, n);
  BOOST_REQUIRE_MESSAGE(status == true, "test_int_serialization: Failed to deserialize vector");

  // Compare vectors
  for (int i = 0; i < n; i++){
    BOOST_REQUIRE_MESSAGE(vec.at(i) == vec_d.at(i), "test_int_serialization: vectors don't match");
  }


  // Cleanup
  delete serial;
}
