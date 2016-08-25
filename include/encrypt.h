#ifndef _encrypt_h
#define _encrypt_h

#include "bin.h"
#include "memory.h"
#include "random.h"
#include "constants.h"

#include <openssl/chacha.h>

//============================================================================

/*!
* Encryptes message
*
* NOTE: Default encrypt uses xor and assumes message is 512 bits
*
* \param[in]  plaintext         Input data.
* \param[out]  key              Key used in
* \param[out] ciphertext        Encrypted output iv||cipher
*
* \return true on success
*/
bool encrypt(Bin* plain_text, Bin *key, Bin* cipher_text); // XOR
bool encrypt_chacha(Bin* plain_text, Bin *key, Bin* cipher_text);

/*!
* Decryptes message
*
* \param[in]   key               Key
* \param[in]   ciphertext        Encrypted data in form iv||cipher
* \param[out]  plaintext         Decrypted text
*
* \return true on success
*/
bool decrypt(Bin* cipher_text, Bin *key, Bin* plain_text); // XOR
bool decrypt_chacha(Bin* cipher_text, Bin *key, Bin* plain_text);

//============================================================================

/*!
* Encrypts/Decryptes message using xor
* Assumes message and key have the same length.
*
* \param[in]   m                 Message to encrypt
* \param[in]   k                 Key to use
* \param[out]  len               Length of message and key
*
* \return true on success
*/
unsigned char * XOR_enc_dec(Bin* m, Bin* k, int len);

/*!
* Encrypts/Decryptes message using chacha
*
* \param[out]  out                Result stored in out
* \param[in]   in                 Message to use
* \param[in]   key                Key to use
* \param[in]  iv                  IV to use
*
* \return true on success
*/
bool chacha(Bin* out, Bin* in, Bin* key, Bin* iv);

//============================================================================
#endif
