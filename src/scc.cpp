#include "scc.h"

//============================================================================

bool apply_blinds(Bin* message, std::vector<BN_BLINDING *> &blinds, std::vector<Bin*> &blinded){
  int r;
  Bin* temp;
  for (unsigned int i = 0; i < blinds.size(); i++){
    temp = new Bin(message->len);
    r = blind(blinds.at(i), message, temp);
    if (r == 1){
      blinded.push_back(temp);
    }
    else {
      // Something went wrong
      return false;
    }
  }

  return true;
}

bool remove_blinds(std::vector<Bin*> &blinded, int len, std::vector<BN_BLINDING *> &blinds,
  std::vector<Bin*> &unblinded){

  int r;
  Bin* temp;
  for (unsigned int i = 0; i < blinds.size(); i++){
    temp = new Bin(len);
    r = unblind(blinds.at(i), blinded.at(i), temp);
    if (r == 1){
      blinded.push_back(temp);
    }
    else {
      // Something went wrong
      return false;
    }
  }

  return true;
}

bool create_blinds(RSA * rsa, int n, std::vector<BN_BLINDING *> &blinds){
  BN_BLINDING * b;
  for (int i=0; i < n; i++){
    b = setup_blinding(rsa);
    // b = setup_blinding_deterministic(rsa);
    if (b != NULL){
      blinds.push_back(b);
    }
    else {
      printf("Couldn't generate blind.");
      return false;
    }
  }

  return true;
}


//============================================================================

int shuffle_random (int i) { return std::rand()%i;}


bool find_indices(std::vector<Bin*> &in, std::vector<Bin*> &what, std::vector<int> &indices)
{
  std::vector<Bin*>::iterator iter;
  size_t id;
  for (unsigned int i = 0; i < what.size(); i++){
    pointer_equal<Bin> predicate = {what.at(i)};
    iter = std::find_if(in.begin(),in.end(), predicate);
    id = iter - in.begin();
    indices.push_back(id);
  }

  return true;
}


//============================================================================

// N is the number of items
bool serialize_vector(Bin* serial, std::vector<Bin*>& vec, int n, int len){
  if (vec.size() != (unsigned int) n){
    printf("serialize_vector: Vec size is %lu, expected %d", vec.size(), n);
    return false;
  }

  serial->len = n * len;
  serial->data = (unsigned char *) tmalloc(serial->len);

  unsigned char *p = serial->data;
  for(int i=0; i < n; i++){

    memcpy(p, vec.at(i)->data, len);
    p = p + len;
  }

  return true;
}

// N is the number of items
bool deserialize_vector(Bin* serial, std::vector<Bin*>& vec, int n, int len){
  if (serial== NULL || serial->len != (len * n)){
    return false;
  }

  Bin *temp = NULL;
  unsigned char *p = serial->data;
  for(int i=0; i < n; i++){
    temp = new Bin(len);
    memcpy(temp->data, p + (len * i), len);
    vec.push_back(temp);
  }

  return true;
}

// N is the number of items
bool serialize_int_vector(Bin* serial, std::vector<int>& vec, int n){
  if (vec.size() != (unsigned int) n){
    printf("serialize_vector: Vec size is %lu, expected %d", vec.size(), n);
    return false;
  }

  int len = sizeof(int);
  serial->len = n * len;
  serial->data = (unsigned char *) tmalloc(serial->len);

  unsigned char *p = serial->data;
  for(int i=0; i < n; i++){

    memcpy(p, &vec.at(i), len);
    p = p + len;
  }

  return true;
}

// N is the number of items
bool deserialize_int_vector(Bin* serial, std::vector<int>& vec, int n){

  int len = sizeof(int);
  if (serial== NULL || serial->len != (len * n)){
    return false;
  }

  int temp;
  unsigned char *p = serial->data;
  for(int i=0; i < n; i++){
    memcpy(&temp, p + (len * i), len);
    vec.push_back(temp);
  }

  return true;
}


//============================================================================
