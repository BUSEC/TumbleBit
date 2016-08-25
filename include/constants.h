#ifndef _constants_h
#define _constants_h

#include <openssl/ripemd.h>
#include <openssl/sha.h>

// SCC
static const unsigned int M = 15 ; // Number of reals
static const unsigned int N = 285; // Number of fakes

// SCC Wrapper
static const int K = 42 ; // SCC Wrapper K reals and K fakes

// Length of key used in commitments
static const unsigned int KEY_LEN = 16; // bytes

// Hash lengths
static const int HASH_512 = SHA512_DIGEST_LENGTH; // bytes
static const int HASH_256 = SHA256_DIGEST_LENGTH; // bytes
static const int HASH_160 = RIPEMD160_DIGEST_LENGTH; // bytes

// Testnet Addresses
const char TUMBLER_ADDRESS[35] = "mzaMTvKBDiYoqkHaDz3w7AmHHETHEQKUiW";
const char ALICE_ADDRESS[35] = "mvESmmYToV1dugQjNdXvA8C8ra6Q2Hyu7d";

// Only change IP - Not port
const char TUMBLER_SERVER_SOCKET[21] = "tcp://localhost:5557";
const char SIGNER_SERVER_SOCKET[21]  = "tcp://localhost:5558";

#endif
