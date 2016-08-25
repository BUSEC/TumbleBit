#ifndef _ec_h
#define _ec_h

#include <stdbool.h>

#include <openssl/pem.h>
#include <openssl/evp.h>

#include "bin.h"
#include "memory.h"
#include "utility.h"
#include "constants.h"

/*!
 * Generates an Elliptic Curve (EC) public/private key pair
 *    using secp256k1 curve.
 *
 * \param[in]   public_suffix       suffix used in filename/path to save public key
 * \param[in]   private_suffix      suffix used in filename/path to save private key
 *
 * \return true on sucess
 */
bool generate_EC_key(const char* public_suffix, const char* private_suffix);


/*!
* Gets the EC private or public key from key_path
*
* \param[in]  key_path       Path to .pem file
* \param[in]  private_key    Bool indicating to fetch private key or not
*
* \return EC_KEY * on success, NULL on failure
*/
EC_KEY * get_ec_key(const char *key_path, bool private_key);


/*!
* Gets the EC private or public key by suffix
*
* \param[in]  suffix         key suffix
* \param[in]  private_key    Bool indicating to fetch private key or not
*
* \return EC_KEY * on success, NULL on failure
*/
EC_KEY * get_ec_key_by_suffix(const char *suffix, bool private_key);


/*!
* Gets the EC key using secret
*
* \param[in]  secret        Secret to use
*
* \return EC_KEY * on success, NULL on failure
*/
EC_KEY * get_key_from_secret(Bin* secret);

//============================================================================


/*!
* Signs a message using ECDSA
*
* \param[in]  key       EC key
* \param[in]  hash      Message to sign
*
* \return ECDSA_SIG * on success, NULL on failure
*/
ECDSA_SIG* EC_sign(EC_KEY * eckey, Bin* hash);

/*!
* Verifies a ECDSA signed message
*
* \param[in]  key         EC key
* \param[in]  hash        Message to sign
* \param[in]  signature   ECDSA signature
*
* \return true when message successfully verifies, false on failure
*/
bool EC_verify (EC_KEY * eckey, Bin* hash, ECDSA_SIG* signature);

/*!
* Converts ECDSA sig to a bitcoin compatible signature -- lower s value
*
* \param[in/out]  sig         ECDSA signature
* \param[in]      key         EC key
*
* \return true when message successfully verifies, false on failure
*/
bool convert_sig_to_standard_der(ECDSA_SIG *sig, EC_KEY *key);

//============================================================================

/*!
* Serializes a ECDSA_SIG
* Allocates a pointer that saves the serial representation that should freed later.
*
* \param[in]  sig         ECDSA signature
* \param[out] serial      Bin to save result
*
* \return true on success
*/
bool serialize_ec_signature(ECDSA_SIG *sig, Bin* serial);
bool serialize_ec_signature_der(ECDSA_SIG *sig, Bin* serial);

/*!
* Deserializes a ECDSA_SIG
*
* \param[in]  serial      Serial representation of ECDSA signature
*
* \return ECDSA_SIG * on success, NULL on failure
*/
ECDSA_SIG *deserialize_ec_signature(Bin* serial);
ECDSA_SIG *deserialize_ec_signature_der(Bin* serial);

//============================================================================


/*!
* Serializes a ec public key.
*
* \param[in]  key         ECDSA signature
* \param[out] serial      Bin to save result
*
* \return true on success
*/
bool serialize_ec_publickey(EC_KEY *key, Bin* serial);


/*!
* Deserializes a public ec key
*
* \param[in]  serial   Serial representation of  ec public key
*
* \return EC_KEY* on success, NULL on failure
*/
EC_KEY* deserialize_ec_publickey(Bin* serial);


/*!
* Note: Might not be needed
* Serializes a ec private key.
* Allocates a pointer that saves the serial representation that should freed later.
*
* \param[in]  key         EC private key
* \param[out] serial      Bin to save result
*
* \return true on success
*/
bool serialize_ec_privatekey(EC_KEY *key, Bin* serial);


#endif
