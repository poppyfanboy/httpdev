#ifndef DEVSERVER_COMMON
#define DEVSERVER_COMMON

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef ptrdiff_t isize;

#define countof(array) ((isize)sizeof(array) / (isize)sizeof((array)[0]))
#define lengthof(string) ((isize)sizeof(string) - 1)

#endif
