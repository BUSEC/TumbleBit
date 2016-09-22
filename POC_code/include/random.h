#ifndef _random_h
#define _random_h

#include "bin.h"
#include "memory.h"
#include "utility.h"
#include <openssl/bn.h>

/*!
* Generates a random number of bits length
*
* \param[in]   bits         bits to generate
*
* \return a random number of n bits
*/
unsigned char * get_random(int bits);

/*!
* Generates a random number of bits length less than n
*
* \param[in]   bits         bits to generate
* \param[in]   n            A BIGNUM
*
* \return a random number of n bits
*/
unsigned char * get_random(int bits, BIGNUM *n);

#endif
