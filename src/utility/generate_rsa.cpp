#include "utility.h"
#include "blind_rsa.h"

int main(){
  // Cron job to generate new RSA key after every epoch
  char * suffix = (char *) "signer";
  generate_rsa_key(2048, suffix, suffix);
}
