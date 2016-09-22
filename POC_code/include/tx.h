#ifndef _tx_h
#define _tx_h


#include "utility.h"
#include "network.h"
#include "constants.h"
#include "hash.h"
#include "scc.h"

/*!
* Gets the signature hash of a transaction spending from a P2SH address
* Funds go to specified address
*
* \param[in]   redeem_script       P2SH redeem script
* \param[in]   address             Output address
* \param[in]   funding_tx_id       TXid of P2SH funding TX
* \param[out]  raw_tx              TX in raw byte form
* \param[out]  sig_hash            Signature Hash
*
* \return true on success
*/
bool get_tx(Bin* redeem_script, Bin* address, Bin* funding_tx_id, Bin* raw_tx, Bin* sig_hash, bool preimage=false);

/*!
* Gets the signature hash of a transaction spending from a P2SH address
* Funds go to the returned random address (different address for each call)
*
* \param[in]   redeem_script       P2SH redeem script
* \param[in]   funding_tx_id       TXid of P2SH funding TX
* \param[out]  sig_hash            Signature Hash
* \param[out]  address             Output address
*
* \return true on success
*/
bool get_tx_with_address(Bin* redeem_script, Bin* funding_tx_id, Bin* sig_hash, Bin* address);

/*!
* Gets the txid of the raw trandaction as a hex string
*
* \param[in]   tx       raw tx in byte form
* \param[out]  tx_id    hex form big endian
*
* \return true on success
*/
bool get_id_from_tx(Bin* tx, Bin* tx_id);

/*!
* Gets the signature hash of a transaction refunding from a P2SH address
* Funds go to specified address
*
* \param[in]   redeem_script       P2SH redeem script
* \param[in]   address             Output address
* \param[in]   funding_tx_id       TXid of P2SH funding TX
* \param[in]   lock_time           The block the tx is locked to
* \param[out]  raw_tx              TX in raw byte form
* \param[out]  sig_hash            Signature Hash
*
* \return true on success
*/
bool get_refund_tx(Bin* redeem_script, Bin* address, Bin* funding_tx_id, Bin* lock_time, Bin* raw_tx, Bin* sig_hash);

/*!
* Creates a transaction that fulfills refunds the funds in the P2SH
* Returns the complete raw tx that can be posted
*
* \param[in]   signature           EC signature of funder
* \param[in]   raw_tx              TX in raw byte form
* \param[in]   redeem_script       P2SH redeem script
* \param[out]  refund_tx           Complete TX in raw byte form
*
* \return true on success
*/
bool send_refund_tx(Bin* signature, Bin* raw_tx, Bin* redeem_script, Bin* refund_tx);

/*!
* Sets up and funds a preimage P2SH address
*
* \param[in]   real_hashes         The images vector
* \param[in]   funder_pubkey       EC public key of funder
* \param[in]   redeemer_pubkey     EC public key of redeemer
* \param[out]  redeem_script       P2SH redeem script
* \param[out]  funding_tx_id       TXid of P2SH funding TX
*
* \return true on success
*/
bool setup_preimage(std::vector<Bin*>& real_hashes, Bin* funder_pubkey, Bin* redeemer_pubkey, Bin* redeem_script, Bin* funding_tx_id, Bin* p2sh_address, Bin* lock_time);

/*!
* Creates a transaction that fulfills that preimage P2SH conditions
* Returns the complete raw tx that can be posted
*
* \param[in]   real_keys           The preimage vector
* \param[in]   redeem_script       P2SH redeem script
* \param[in]   raw_tx              TX in raw byte form
* \param[in]   redeemer_sig        EC signature of redeemer
* \param[out]  tx_fulfill          Complete TX in raw byte form
*
* \return true on success
*/
bool spend_preimage(std::vector<Bin*>& real_keys, Bin* redeem_script, Bin*raw_tx, Bin* redeemer_sig, Bin* tx_fulfill);

/*!
* Extracts the keys (images) in serial form from the raw tx that
* fulfills the conditions of the preimage P2SH
*
* \param[in]   tx_fulfill          Complete TX in raw byte form
* \param[out]  serial_real_keys    Keys in serial form
*
* \return true on success
*/
bool get_keys_from_tx(Bin* tx_fulfill, Bin* serial_real_keys);

/*!
* Sets up and funds a 2-of-2 escrow P2SH address
*
* \param[in]   payer_pubkey        EC public key of funder
* \param[in]   redeemer_pubkey     EC public key of redeemer
* \param[out]  redeem_script       P2SH redeem script
* \param[out]  funding_tx_id       TXid of P2SH funding TX
*
* \return true on success
*/
bool setup_escrow(Bin* payer_pubkey, Bin* redeemer_pubkey, Bin* redeem_script, Bin* funding_tx_id, Bin* p2sh_address, Bin* lock_time);


/*!
* Creates a transaction that fulfills that escrow P2SH conditions
* Returns the complete raw tx that can be posted
*
* \param[in]   raw_tx              TX in raw byte form
* \param[in]   payer_sig           EC signature of redeemer
* \param[in]   redeemer_sig        EC signature of redeemer
* \param[in]   address             Output address
* \param[in]   redeem_script       P2SH redeem script
* \param[in]   funding_tx_id       TXid of P2SH funding TX
* \param[out]  tx_fulfill          Complete TX in raw byte form
*
* \return true on success
*/
bool spend_escrow(Bin* payer_sig, Bin* redeemer_sig, Bin* address, Bin* redeem_script, Bin* funding_tx_id, Bin* tx_fulfill);

#endif
