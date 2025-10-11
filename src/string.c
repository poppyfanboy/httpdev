#include <string.h> // strncmp

#include "common.h"

#define SV(string) (StringView){string, lengthof(string)}

typedef struct {
    char const *data;
    isize size;
} StringView;

StringView string_from_range(char const *begin, char const *end) {
    return (StringView){
        .data = begin,
        .size = end - begin,
    };
}

bool string_starts_with(StringView haystack, StringView needle) {
    if (needle.size > haystack.size) {
        return false;
    }

    return strncmp(haystack.data, needle.data, needle.size) == 0;
}

bool string_ends_with(StringView haystack, StringView needle) {
    if (needle.size > haystack.size) {
        return false;
    }

    return strncmp(haystack.data + (haystack.size - needle.size), needle.data, needle.size) == 0;
}

bool string_equals(StringView left, StringView right) {
    if (left.size != right.size) {
        return false;
    }

    return memcmp(left.data, right.data, right.size) == 0;
}
