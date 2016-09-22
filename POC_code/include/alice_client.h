
#ifndef _alice_client_h
#define _alice_client_h

#include "assert.h"

// Local
#include "alice.h"
#include "scc_interface.h"
#include "network.h"

/*!
* Runs the client (Alice) for the scc protocol
* to get a decryption of y and save in y_sk.
*
* \param[in]   y          An item encrypted with rsa
* \param[out]  y_sk       A decryption of the item
*
* \return true on success, false on error.
*/
bool get_decryption(Bin* y, Bin* y_sk);


#endif
