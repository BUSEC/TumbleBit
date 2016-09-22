#ifndef _blind_rsa_h
#define _blind_rsa_h

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#include "bin.h"
#include "memory.h"
#include "utility.h"

/*!
* Notes:
*       - Key path to public and private keys are in
*         PUBLIC & PRIVATE
*       - RSA keys are blinded when loaded to protect
*         against timing attacks
*/

#define PUBLIC  "./keys/public_"
#define PRIVATE "./keys/private_"
#define EXT     ".pem"

//============================================================================

/*!
 * Generates an RSA public/private key pair of size n bits
 *
 * \param[in]   bits                size of RSA key in bits
 * \param[in]   public_suffix       suffix to be used in filename/path to save public key
 * \param[in]   private_suffix      suffix to be used in filename/path to save private key
 * \param[out]  rsa                 RSA public key.
 *
 * \return true on sucess
 */
bool generate_rsa_key(int bits, char* public_suffix, char* private_suffix);


/*!
 * Loads RSA public key of size n bits and turns on key blinding.
 *
 * \param[in]   bits       size of RSA key in bits
 * \param[in]   suffix     suffix to be used in path to search for key
 *
 * \return a pointer to the RSA struct
 */
RSA * get_public_rsa(int bits, char *suffix);

/*!
 * Loads RSA public and private keys of size n bits  and turns on key blinding.
 *
 * \param[in]   bits       size of RSA key in bits
 * \param[in]   suffix     suffix to be used in path to search for key
 *
 * \return a pointer to the RSA struct
 */
RSA * get_private_rsa(int bits, char *suffix);

//============================================================================

/*!
 * Setup BN_Blinding structure.
 *
 * \param[in]  rsa       RSA public key.
 *
 * \return initalized BN_Blinding structure, NULL on error.
 */
BN_BLINDING * setup_blinding(RSA *rsa);

/*!
 * Setup BN_Blinding structure using r.
 *
 * \param[in]  rsa       RSA public key.
 * \param[in]  r         Random value of length RSA_size(rsa)
 *
 * \return initalized BN_Blinding structure, NULL on error.
 */
BN_BLINDING * setup_blinding(RSA *rsa, Bin* r);


/*!
* Blind data and store result in unblind
*
* \param[in]  blinding  BN_Blinding initialized struct.
* \param[in]  msg       Input data.
* \param[out] blinded   Output buffer.
*
* \return true on success, false on error.
*/
bool blind(BN_BLINDING * blinding, Bin* msg, Bin* blinded);

/*!
* Unblind data and store result in unblind
*
* \param[in]  blinding    BN_Blinding initialized struct.
* \param[in]  rsa         RSA public key.
* \param[in]  msg         Input data.
* \param[out] unblinded   Output buffer.
*
* \return true on success, false on error.
*/
bool unblind(BN_BLINDING * blinding, Bin* msg, Bin* unblinded);

/*!
* Unblind data and store result in reverted
*
* \param[in]  rsa       RSA public key.
* \param[in]  message   Blinded data
* \param[in]  A         The blind that was applied to the message
* \param[out] reverted  data with blind removed
*
* \return true on success, false on error.
*/
bool revert_blind(RSA *rsa, Bin* message, Bin* A, Bin* reverted);

//============================================================================

/*!
* Verify RSA Signature.
*
* \param[in]  rsa       RSA public key.
* \param[in]  msg       Input data.
* \param[out] sig       Output buffer.
*
* \return true on success, false on error.
*/
bool verify(RSA *rsa, Bin* msg, Bin* sig);

/*!
*  Sign Message using RSA.
*
* \param[in]  rsa       RSA public key.
* \param[in]  msg       Input data.
* \param[out] sig       Output buffer.
*
* \return true on success, false on error.
*/
bool sign(RSA *rsa, Bin* msg, Bin* sig);


#endif
