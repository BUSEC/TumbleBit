#include "utility.h"
#include "constants.h"

int BNToBin(BIGNUM *f, unsigned char * bin, int bin_len){
  // We make the assumption that all bin representations of BIGNUMs will be the
  //same length. In semi-rare cases the bignum use than data_len bytes.  Such
  //cases mean that less than data_len bytes will be written into bin, thus bin
  //will contain uninitialized values. We fix this by packeting zeros in the
  //front of bignum. Zeros will not impact the magnitude of bin, but will ensure
  //that all bytes are initalized.

  if (f == NULL || bin == NULL){
    return 0;
  }

  int offset = bin_len-BN_num_bytes(f);

  int ret = BN_bn2bin(f, bin+offset);

  // Zero out any bytes not written to in BN_bn2bin.
  int i;
  for(i = 0; i < offset; i++){
      bin[i] = 0x00;
  }

  return ret+offset;
}

//============================================================================
//======= Printing Methods
//============================================================================

void print_BN(BIGNUM* bn){
  char * r = BN_bn2hex(bn);
  printf("%s\n", r);
}


void print_hex(int len, unsigned char *data){
  int x;
  for(x=0;x<len;x++){
    printf("%02x", data[x]);
  }
  printf("\n");
}

void print_blind(BN_BLINDING* blind){

  printf("R is:\n");
  char * r = BN_bn2hex(blind->A);
  printf("%s\n", r);


  printf("R inverse is:\n");
  char * ri = BN_bn2hex(blind->Ai);
  printf("%s\n", ri);

}

void print_blinds(std::vector<BN_BLINDING *> blinds){

  for(unsigned int i=0; i < blinds.size(); i++){
    printf("Blind #%d is:\n", i);
    print_blind(blinds.at(i));
    printf("\n");
  }
}

//============================================================================
//======= String Representation Methods
//============================================================================

char * get_hex_str_rev(Bin* msg){
  int len = msg->len;
  char *buffer = (char *) tmalloc( (2*len) + 1);

  int x = 0;
  for(int i = len-1; i >= 0; i--) {
    sprintf(&buffer[x*2], "%02x", msg->data[i]);
    x++;
  }

  return buffer;
}

char * get_hex_str(Bin* msg){
  int len = msg->len;
  char *buffer = (char *) tmalloc( (2*len) + 1);

  int x;
  for(x = 0; x < len; x++) {
    sprintf(&buffer[x*2], "%02x", msg->data[x]);
  }

  return buffer;
}
