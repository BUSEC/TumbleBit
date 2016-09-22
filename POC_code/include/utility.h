#ifndef _utility_h
#define _utility_h

#include "bin.h"
#include "memory.h"
#include <vector>
#include <openssl/bn.h>


// Need this to print/access blinding struct values
struct bn_blinding_st
	{
	BIGNUM *A;
	BIGNUM *Ai;
	BIGNUM *e;
	BIGNUM *mod; /* just a reference */
	};

//============================================================================

/*!
 * Serialize a BigNum f to a buffer of fixed length.
 *
 * \param[in]  f        Bignum to be serialized.
 * \param[out] bin      Binary string which f is serialized into.
 * \param[in]  bin_len  Length of bin.
 *
 * \return Size of bytes serialized.
 */
int BNToBin(BIGNUM *f, unsigned char * bin, int bin_len);

//============================================================================

/*!
*  Prints bignum data in hex form
*
* \param[in]  bn          a BIGNUM
*
*/
void print_BN(BIGNUM* bn);

/*!
*  Prints input data in hex form
*
* \param[in]  len         Length of data
* \param[in] data        The string to print out in hex format
*
*/
void print_hex(int len, unsigned char *data);

/*!
*  Prints out all the key/strings in the vector.
*
* \param[int] m        A vector of strings (keys)
*
*/
void print_keys(std::vector<unsigned char *> m);

/*!
*  Prints out R and R inverse from the blinding struct
*
* \param[int] blind        An initilizes blinding struct
*
*/
void print_blind(BN_BLINDING* blind);

/*!
*  Prints out R and R inverse for all the blinds in the vector.
*
* \param[int] blinds        A vector of blinds (BN_BLINDING)
*
*/
void print_blinds(std::vector<BN_BLINDING *> blinds);

//============================================================================

/*!
*  Returns a pointer to the hex form of the input
*
* \param[in]  msg        in bin format
*
*/
char * get_hex_str(Bin* msg);

/*!
*  Returns a pointer to the reversed hex form of the input
*
* \param[in]  msg        in bin format
*
*/
char * get_hex_str_rev(Bin* msg);

//============================================================================

#endif
