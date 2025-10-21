#ifndef HTTPDEV_COMMON
#define HTTPDEV_COMMON

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SHORT_NAMES_FOR_PRIMITIVE_TYPES_WERE_DEFINED
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef ptrdiff_t isize;

#define countof(array) ((isize)sizeof(array) / (isize)sizeof((array)[0]))
#define lengthof(string) ((isize)sizeof(string) - 1)

// Ignores newlines and repeated whitespaces, still mostly good enough for stringifying source code.
#define SRC(...) #__VA_ARGS__

#endif
