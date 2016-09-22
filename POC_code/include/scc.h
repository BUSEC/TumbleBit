
#ifndef _scc_h
#define _scc_h

#include "utility.h"
#include "blind_rsa.h"

#include <vector>
#include <algorithm>
#include <iostream>
#include <string.h>
#include <stdlib.h>

//============================================================================

/*!
* Applies blinds to message
*
* \param[in]  message   A message to blind
* \param[in]  blinds    A vector of initilized BN_BLINDING structs.
* \param[out] blinded   A vector that will hold the blinded m's.
*
* \return true on success, false on error.
*/
bool apply_blinds(Bin* message, std::vector<BN_BLINDING *> &blinds, std::vector<Bin*> &blinded);

/*!
* Removes the blinds from the messages in blinded
*
* \param[out] blinded   A vector that holds blinded messages.
* \param[in]  m_len     Length of the blinded message.
* \param[in]  blinds    A vector of initilized BN_BLINDING structs.
* \param[out] blinded   A vector that will hold the unblinded messages.
*
* \return true on success, false on error.
*/
bool remove_blinds(std::vector<Bin*> &blinded, int len, std::vector<BN_BLINDING *> &blinds,
  std::vector<Bin*> &unblinded);

/*!
* Generate blinding factors
*
* \param[in]   rsa       RSA public key.
* \param[in]   n         Number of blinds to generate
* \param[out]  blinds    A vector to store the initilized BN_BLINDING structs.
*
* \return true on success, false on error.
*/
bool create_blinds(RSA * rsa, int n, std::vector<BN_BLINDING *> &blinds);

//============================================================================


/*!
* Finds the indices of the elements of the "what" vector in "in" vector
*
* \param[in]   in         The main vector
* \param[in]   what       The subvector to find the indices for
* \param[out]  indices    A vector of indices for what
*
* \return true on success, false on error.
*/
bool find_indices(std::vector<Bin*> &in, std::vector<Bin*> &what, std::vector<int> &indices);

//============================================================================

/*!
* Serializes a vector of size n with items of len
*
* \param[out]  serial   Serial representation
* \param[in]   vec       Vector to store results in
* \param[in]   n        Number of items
* \param[in]   len      Length of items
*
* \return true on success, false on error.
*/
bool serialize_vector(Bin* serial, std::vector<Bin*>& vec, int n, int len);


/*!
* Deserializes to a vector of size n with items of len
*
* \param[in]    serial   Serial representation
* \param[out]   vec      Vector to store results in
* \param[in]    n        Number of items
* \param[in]    len      Length of items
*
* \return true on success, false on error.
*/
bool deserialize_vector(Bin* serial, std::vector<Bin*>& vec, int n, int len);


/*!
* Serializes a integer vector of size n
*
* \param[out]  serial   Serial representation
* \param[in]   vec       Vector to store results in
* \param[in]   n        Number of items
*
* \return true on success, false on error.
*/
bool serialize_int_vector(Bin* serial, std::vector<int>& vec, int n);


/*!
* Deserializes to an integer vector of size N
*
* \param[in]    serial   Serial representation
* \param[out]   vec      Vector to store results in
* \param[in]    n        Number of items
*
* \return true on success, false on error.
*/
bool deserialize_int_vector(Bin* serial, std::vector<int>& vec, int n);

//============================================================================
#endif
