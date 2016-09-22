#ifndef _memory_h
#define _memory_h

// Local
#include "bin.h"

// C
#include <stdlib.h>
// #include <strings.h>
#include <limits.h>
#include <string.h>

// C++
#include <vector>
#include <iostream>

// SSL
#include <openssl/bn.h>


void tfree(void *ptr);
void* tmalloc(size_t size);


/*!
*  Frees BN_BLINDING structs pointed to in the vector
*
* \param[int]  b      A vector of BN_BLINDING structs
*
*/
void free_blinds(std::vector<BN_BLINDING *> b);

/*!
*  Frees Bin objects pointed to in the vector
*
* \param[int] bins      A vector of Bin pointers
*
*/
void free_Bins(std::vector<Bin*> bins);

int timingsafe_memcmp(const void *b1, const void *b2, size_t len);


#endif
