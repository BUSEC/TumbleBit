#ifndef _hash_h
#define _hash_h

#include <openssl/rsa.h>
#include <openssl/hmac.h>

#include "bin.h"
#include "memory.h"
#include "constants.h"

/*!
* Compute Full Domain Hash.
*
* \param[in]  rsa       RSA public key.
* \param[in]  msg       Input data.
* \param[in]  hash      Hash function.
*
* \return pointer to the msg hash, NULL on error.
*/
Bin* full_domain_hash(RSA *rsa, Bin* msg, const EVP_MD *hash);

/*!
* Compute SHA256(SHA256(msg))
*
* \param[in]  msg       Input data.
*
* \return pointer to the msg hash, NULL on error.
*/
Bin* hash256(Bin* msg);

/*!
* Compute hmac SHA256 of msg.
*
* \param[in]  msg       Input data.
*
* \return pointer to the msg hash, NULL on error.
*/
Bin* hmac256(Bin* msg, Bin* key);

#endif
