#include <assert.h> // assert
#include <string.h> // memset, memcpy
#include <stdlib.h> // malloc, free

#include "common.h"
#include "string.c"

typedef enum {
    HTTP_GET,
} HttpMethod;

typedef struct {
    char *data;
    StringView method;
    StringView uri;
    StringView version;
} HttpRequestLine;

typedef enum {
    HTTP_READ_ERROR = -1,
    HTTP_READ_BEGIN = 0,

    HTTP_READ_REQUEST_LINE,
    HTTP_READ_HEADER,
    HTTP_READ_BODY,

    HTTP_READ_FINISH,
} HttpReaderState;

typedef struct {
    HttpReaderState state;
    struct {
        char *data;
        isize size;
        isize capacity;
    } partial;

    HttpRequestLine request_line;
    char *body; isize body_size;

    isize content_length;

    bool is_websocket;
    String websocket_key;
} HttpReader;

HttpReader *http_reader_create(void) {
    HttpReader *reader = malloc(sizeof(HttpReader));
    memset(reader, 0, sizeof(HttpReader));

    // Capacity corresponds to the largest request-line/header-line we will be able to handle.
    reader->partial.data = malloc(4096);
    reader->partial.size = 0;
    reader->partial.capacity = 4096;

    return reader;
}

void http_reader_destroy(HttpReader *reader) {
    free(reader->partial.data);
    string_destroy(&reader->websocket_key);

    if (reader->request_line.data != NULL) {
        free(reader->request_line.data);
    }

    if (reader->body != NULL) {
        free(reader->body);
    }

    free(reader);
}

bool http_reader_done(HttpReader const *reader) {
    return reader->state == HTTP_READ_FINISH || reader->state == HTTP_READ_ERROR;
}

bool eat_word(char const **begin, char const *end) {
    char const *iter = *begin;
    while (iter < end) {
        if (*iter == ' ' || 0 <= *iter && *iter <= 31 || *iter >= 127) {
            *begin = iter;
            return true;
        }

        iter += 1;
    }

    *begin = iter;
    return false;
}

// "Token" is defined as follows: https://www.rfc-editor.org/rfc/rfc2616#section-2.2
bool eat_token(char const **begin, char const *end) {
    char const *iter = *begin;
    while (iter < end) {
        if (0 <= *iter && *iter <= 31 || *iter >= 127) {
            *begin = iter;
            return true;
        }
        if (
            *iter == '(' || *iter == ')' || *iter == '<' || *iter == '>'  || *iter == '@'  ||
            *iter == ',' || *iter == ';' || *iter == ':' || *iter == '\\' || *iter == '\'' ||
            *iter == '/' || *iter == '[' || *iter == ']' || *iter == '?'  || *iter == '='  ||
            *iter == '{' || *iter == '}' || *iter == ' '
        ) {
            *begin = iter;
            return true;
        }

        iter += 1;
    }

    *begin = iter;
    return true;
}

bool eat_line(char const **begin, char const *end) {
    char const *iter = *begin;
    while (iter < end) {
        if (end - iter == 1 && iter[0] == '\r') {
            *begin = iter;
            return false;
        }
        if (end - iter >= 2 && iter[0] == '\r' && iter[1] == '\n') {
            iter += 2;
            *begin = iter;
            return true;
        }

        iter += 1;
    }

    *begin = iter;
    return false;
}

bool eat_until_newline(char const **begin, char const *end) {
    char const *iter = *begin;
    while (iter < end) {
        if (end - iter == 1 && iter[0] == '\r') {
            *begin = iter;
            return false;
        }
        if (end - iter >= 2 && iter[0] == '\r' && iter[1] == '\n') {
            *begin = iter;
            return true;
        }

        iter += 1;
    }

    *begin = iter;
    return false;
}

bool eat_char(char const **begin, char const *end, char expected_char) {
    if (end - *begin >= 1 && (*begin)[0] == expected_char) {
        *begin += 1;
        return true;
    } else {
        return false;
    }
}

bool eat_newline(char const **begin, char const *end) {
    if (end - *begin >= 2 && (*begin)[0] == '\r' && (*begin)[1] == '\n') {
        *begin += 2;
        return true;
    } else {
        return false;
    }
}

void skip_whitespaces(char const **begin, char const *end) {
    char const *iter = *begin;
    while (iter < end && *iter == ' ') {
        iter += 1;
    }

    *begin = iter;
}

bool http_read_request_line(HttpReader *reader, char const **begin, char const *end) {
    char const *iter = *begin;
    bool newline_found = eat_line(&iter, end);

    if (reader->partial.size + (iter - *begin) > reader->partial.capacity) {
        reader->state = HTTP_READ_ERROR;
        return false;
    }
    memcpy(reader->partial.data + reader->partial.size, *begin, iter - *begin);
    reader->partial.size += iter - *begin;

    if (newline_found) {
        reader->request_line.data = malloc(reader->partial.size);
        memcpy(reader->request_line.data, reader->partial.data, reader->partial.size);

        char const *request_line_iter = reader->request_line.data;
        char const *request_line_end = reader->request_line.data + reader->partial.size;

        reader->partial.size = 0;

        char const *method_begin = request_line_iter;
        eat_word(&request_line_iter, request_line_end);
        reader->request_line.method = string_from_range(method_begin, request_line_iter);
        if (!eat_char(&request_line_iter, request_line_end, ' ')) {
            reader->state = HTTP_READ_ERROR;
            return false;
        }

        char const *uri_begin = request_line_iter;
        eat_word(&request_line_iter, request_line_end);
        reader->request_line.uri = string_from_range(uri_begin, request_line_iter);
        if (!eat_char(&request_line_iter, request_line_end, ' ')) {
            reader->state = HTTP_READ_ERROR;
            return false;
        }

        char const *version_begin = request_line_iter;
        eat_word(&request_line_iter, request_line_end);
        reader->request_line.version = string_from_range(version_begin, request_line_iter);
        if (!eat_newline(&request_line_iter, request_line_end)) {
            reader->state = HTTP_READ_ERROR;
            return false;
        }

        *begin = iter;
        return true;
    }

    *begin = iter;
    return false;
}

bool http_read_header(HttpReader *reader, char const **begin, char const *end) {
    char const *iter = *begin;
    bool newline_found = eat_line(&iter, end);

    if (reader->partial.size + (iter - *begin) > reader->partial.capacity) {
        reader->state = HTTP_READ_ERROR;
        return false;
    }
    memcpy(reader->partial.data + reader->partial.size, *begin, iter - *begin);
    reader->partial.size += iter - *begin;

    if (newline_found) {
        char const *header_line_iter = reader->partial.data;
        char const *header_line_end = reader->partial.data + reader->partial.size;

        char const *header_name_begin = header_line_iter;
        if (!eat_token(&header_line_iter, header_line_end)) {
            reader->state = HTTP_READ_ERROR;
            return false;
        }
        StringView header_name = string_from_range(header_name_begin, header_line_iter);

        eat_char(&header_line_iter, header_line_end, ':');
        skip_whitespaces(&header_line_iter, header_line_end);

        char const *header_value_begin = header_line_iter;
        eat_until_newline(&header_line_iter, header_line_end);
        StringView header_value = string_from_range(header_value_begin, header_line_iter);

        if (
            string_equals(header_name, SV("Upgrade")) &&
            string_equals(header_value, SV("websocket"))
        ) {
            reader->is_websocket = true;
        }

        if (
            string_equals(header_name, SV("Sec-WebSocket-Key")) &&
            header_value.size > 0
        ) {
            reader->websocket_key = string_clone(header_value);
        }

        eat_newline(&header_line_iter, header_line_end);
        assert(header_line_iter == header_line_end);

        reader->partial.size = 0;

        *begin = iter;
        return true;
    }

    *begin = iter;
    return false;
}

isize http_read_body(HttpReader *reader, char const **begin, char const *end) {
    return true;
}

isize http_reader_feed(HttpReader *reader, char const *data, isize data_size) {
    char const *data_iter = data;
    char const *data_end = data + data_size;

    while (data_iter < data_end && !http_reader_done(reader)) {
        if (reader->state == HTTP_READ_BEGIN) {
            reader->state = HTTP_READ_REQUEST_LINE;
            continue;
        }

        if (reader->state == HTTP_READ_REQUEST_LINE) {
            if (http_read_request_line(reader, &data_iter, data_end)) {
                reader->state = HTTP_READ_HEADER;
                continue;
            }
        }

        if (reader->state == HTTP_READ_HEADER) {
            if (reader->partial.size == 0 && eat_newline(&data_iter, data_end)) {
                // TODO: Actually parse Content-Length from headers.
                if (reader->content_length > 0) {
                    reader->state = HTTP_READ_BODY;
                } else {
                    reader->state = HTTP_READ_FINISH;
                }
                continue;
            }

            if (http_read_header(reader, &data_iter, data_end)) {
                reader->state = HTTP_READ_HEADER;
                continue;
            }
        }

        if (reader->state == HTTP_READ_BODY) {
            if (http_read_body(reader, &data_iter, data_end)) {
                reader->state = HTTP_READ_FINISH;
                continue;
            }
        }

        break;
    }

    return data_iter - data;
}
