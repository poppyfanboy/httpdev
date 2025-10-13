#include <stdlib.h> // malloc, free
#include <string.h> // strncmp, memcpy

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

typedef struct {
    char *data;
    isize size;
    isize capacity;
} String;

StringView string_view(String const *string) {
    return (StringView){string->data, string->size};
}

String string_clone(StringView source) {
    String string = {
        .data = malloc(source.size + 1),
        .size = source.size,
        .capacity = source.size,
    };

    memcpy(string.data, source.data, source.size);
    string.data[string.size] = '\0';

    return string;
}

void string_append(String *dest, StringView string) {
    if (dest->capacity - dest->size < string.size) {
        dest->data = realloc(dest->data, dest->size + string.size + 1);
        dest->capacity = dest->size + string.size;
        dest->data[dest->capacity] = '\0';
    }
    memcpy(dest->data + dest->size, string.data, string.size);
    dest->size += string.size;
}

void string_destroy(String *string) {
    if (string->data != NULL) {
        free(string->data);
        string->data = NULL;
        string->size = 0;
        string->capacity = 0;
    }
}
