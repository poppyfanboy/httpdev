#ifndef DEVSERVER_COMMON
#define DEVSERVER_COMMON

#include <stdbool.h>
#include <stddef.h>

typedef ptrdiff_t isize;

#define lengthof(string) ((isize)sizeof(string) - 1)

#endif
