#include <stdlib.h> // malloc, free
#include <string.h> // strncmp, memcpy
#include <stdarg.h> // va_list, va_start, va_end
#include <stdio.h>  // vsnprintf

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

String string_empty(void) {
    return (String){
        .data = "",
        .size = 0,
        .capacity = 0,
    };
}

void string_reserve(String *string, isize new_capacity) {
    if (string->capacity >= new_capacity) {
        return;
    }

    if (string->capacity == 0) {
        string->data = malloc(new_capacity + 1);
    } else {
        string->data = realloc(string->data, new_capacity + 1);
    }
    string->capacity = new_capacity;

    // memset() would've been harder to break than this, but these are more like guardrails anyway.
    string->data[string->size] = '\0';
    string->data[string->capacity] = '\0';
}

void string_append_format(String *string, char const *format, ...) {
    va_list args;

    va_start(args, format);
    isize append_size = vsnprintf(NULL, 0, format, args);
    va_end(args);

    string_reserve(string, string->size + append_size);

    va_start(args, format);
    vsnprintf(string->data + string->size, append_size + 1, format, args);
    va_end(args);

    string->size += append_size;
    string->data[string->size] = '\0';
}

void string_append(String *dest, StringView string) {
    string_reserve(dest, dest->size + string.size);

    memcpy(dest->data + dest->size, string.data, string.size);

    dest->size += string.size;
    dest->data[dest->size] = '\0';
}

String string_clone(StringView source) {
    String string = string_empty();
    string_append(&string, source);
    return string;
}

void string_destroy(String *string) {
    if (string->size > 0) {
        free(string->data);
        string->data = "";
        string->size = 0;
        string->capacity = 0;
    }
}
