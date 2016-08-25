#ifndef _bin_h
#define _bin_h

#include <string.h>
#include <stdlib.h>

class Bin
{
public:
  unsigned char * data;
  int len;

  // Constructors & Destructors
  Bin(){};
  Bin(int len_c);
  Bin(int len_c, unsigned char *data_c);
  Bin(const Bin &bin);

  ~Bin();

  // Methods
  unsigned char * serialize();
  void print();

  bool operator== (const Bin& b) const;
  bool operator!= (const Bin& b);
};

template <typename T>
struct pointer_equal
{
    const T* to_find;

    bool operator()(const T* other) const
    {
        return  *to_find == *other;
    }
};

// True if item is not null and len > 1
bool defined(Bin* item);
void delete_bin(Bin* item);

#endif
