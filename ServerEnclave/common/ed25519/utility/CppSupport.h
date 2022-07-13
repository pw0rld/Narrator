#ifndef CPP_SUPPORT_H
#define CPP_SUPPORT_H

#include <stdlib.h>

extern "C"
{

  void __cxa_pure_virtual()
  {
    while (1)
      ;
  }

  // void operator delete(void * p) // or delete(void *, std::size_t)
  // {
  //   free(p);
  // }
}

#endif // CPP_SUPPORT_H
