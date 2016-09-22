#include "bin.h"
#include "utility.h"
#include "memory.h"

//============================================================================
//======= Constructors and Destructors
//============================================================================

Bin::Bin(int len_c){
  len = len_c;
  data = (unsigned char *) tmalloc(len);
}

Bin::Bin(int len_c, unsigned char *data_c){
  len = len_c;
  data = data_c;
}

// Copy constructor
Bin::Bin(const Bin &bin)
{
  len = bin.len;
  data = (unsigned char *) tmalloc(len);
  memcpy(data, bin.data, len);
}

Bin::~Bin(){
  if (len > 0){
    tfree(data);
  }
  len = 0;
}

bool Bin::operator== (const Bin& b) const
{
  if (len != b.len){
    return false;
  }

  return (memcmp(data, b.data, len) == 0);
}

bool Bin::operator!= (const Bin& b)
{
  if (len != b.len){
    return true;
  }

  return (memcmp(data, b.data, len) != 0);
}

//============================================================================
//======= Public Methods
//============================================================================

unsigned char * Bin::serialize(){
  int int_len = sizeof(int);
  unsigned char * serial = (unsigned char *) malloc(len + int_len);

  memcpy(serial, &len, int_len);
  memcpy(serial + int_len, data, len);

  return serial;
}

void Bin::print(){

  if (len == 0){
    printf("Bin was freed, or is invalid!\n");
    return;
  }

  printf("Len is: %d\n", len);
  printf("Hex is: \n");
  print_hex(len, data);
  printf("\n");
}

//============================================================================
//======= Non-Instance Methods
//============================================================================

bool defined(Bin* item){
  return !(item == NULL || item->len < 1);
}

void delete_bin(Bin* item){
  if (item != NULL){
    delete item;
    item = NULL;
  }
}
