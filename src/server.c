#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <string.h> // memcpy, memmove
#include <stdlib.h> // malloc, free
#include <stdio.h>  // snprintf, fopen, fread, fclose, fseek, ftell

#define PORT "8080"
#define IO_BUFFER_SIZE 4096

#include "common.h"
#include "http.c"

char *http_response_404(isize *response_size) {
    char response_data[] =
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 0\r\n\r\n";

    // Allocate so that we could call free() on the return value.
    char *response = malloc(lengthof(response_data));
    memcpy(response, response_data, lengthof(response_data));

    *response_size = lengthof(response_data);
    return response;
}

char *http_response_file(StringView file_name, isize *response_size) {
    FILE *file = fopen(file_name.data, "rb");
    if (file == NULL) {
        return http_response_404(response_size);
    }

    fseek(file, 0, SEEK_END);
    isize file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char const *mime_type = "application/octet-stream";
    if (string_ends_with(file_name, SV(".html"))) {
        mime_type = "text/html";
    } else if (string_ends_with(file_name, SV(".wasm"))) {
        mime_type = "application/wasm";
    } else if (string_ends_with(file_name, SV(".js"))) {
        mime_type = "application/javascript";
    }

    char headers_format[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: %td\r\n"
        "Content-Type: %s\r\n\r\n";

    isize headers_size = snprintf(
        NULL, 0, headers_format,
        /* Content-Length: */ file_size,
        /* Content-Type: */ mime_type
    );

    char *response = malloc((headers_size + 1) + file_size);
    snprintf(
        response, headers_size + 1, headers_format,
        /* Content-Length: */ file_size,
        /* Content-Type: */ mime_type
    );

    char *response_iter = response + headers_size;
    char *response_end = response + headers_size + file_size;

    // TODO: Stream file responses instead of reading entire files into memory first.
    while (response_iter < response_end) {
        isize bytes_read = fread(response_iter, 1, response_end - response_iter, file);
        if (bytes_read == 0) {
            break;
        }

        response_iter += bytes_read;
    }
    fclose(file);

    *response_size = response_iter - response;
    return response;
}

void socket_send_all(SOCKET socket, char const *data, isize data_size) {
    while (data_size > 0) {
        isize bytes_sent = send(socket, data, data_size, 0);
        data += bytes_sent;
        data_size -= bytes_sent;
    }
}

int main(void) {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return 1;
    }

    struct addrinfo *address_info;
    {
        struct addrinfo address_info_hints = {
            .ai_family = AF_INET,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = IPPROTO_TCP,
            .ai_flags = AI_PASSIVE,
        };
        if (getaddrinfo(NULL, PORT, &address_info_hints, &address_info) != 0) {
            return 1;
        }
    }

    SOCKET listen_socket = socket(
        address_info->ai_family,
        address_info->ai_socktype,
        address_info->ai_protocol
    );
    if (bind(listen_socket, address_info->ai_addr, (int)address_info->ai_addrlen) != 0) {
        return 1;
    }

    listen(listen_socket, SOMAXCONN);

    SOCKET read_sockets[FD_SETSIZE];
    fd_set read_sockets_set;
    isize read_socket_count = 1;
    read_sockets[0] = listen_socket;

    struct {
        char *data;
        isize size;
        isize capacity;
    } input = {malloc(IO_BUFFER_SIZE), 0, IO_BUFFER_SIZE};

    while (true) {
        FD_ZERO(&read_sockets_set);
        for (isize i = 0; i < read_socket_count; i += 1) {
            FD_SET(read_sockets[i], &read_sockets_set);
        }
        select(0, &read_sockets_set, NULL, NULL, NULL);

        for (isize i = 0; i < read_socket_count; i += 1) {
            if (read_sockets[i] == listen_socket) {
                continue;
            }
            if (!FD_ISSET(read_sockets[i], &read_sockets_set)) {
                continue;
            }

            SOCKET client_socket = read_sockets[i];
            bool socket_closed = false, socket_error = false;

            HttpReader *reader = http_reader_create();

            while (!http_reader_done(reader)) {
                int bytes_received = recv(
                    client_socket,
                    input.data + input.size, input.capacity - input.size,
                    0
                );
                if (bytes_received == 0) {
                    socket_closed = true;
                    break;
                }
                if (bytes_received == SOCKET_ERROR) {
                    socket_error = true;
                    break;
                }

                input.size += bytes_received;
                isize bytes_read = http_reader_feed(reader, input.data, input.size);

                memmove(input.data, input.data + bytes_read, input.size - bytes_read);
                input.size -= bytes_read;
            }

            if (!socket_error && reader->state == HTTP_READ_FINISH) {
                char *response = NULL;
                isize response_size = 0;

                if (string_equals(reader->request_line.uri, SV("/"))) {
                    response = http_response_file(SV("index.html"), &response_size);
                }

                if (response == NULL) {
                    response = http_response_404(&response_size);
                }

                socket_send_all(client_socket, response, response_size);
                free(response);

                // https://blog.netherlabs.nl/articles/2009/01/18/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable
                //
                // First shutdown the socket, then wait for the client to close it (select() will
                // detect a read update on this socket later). This still does not guarantee that
                // the client will receive every single byte, but I don't know what else can I do.
                shutdown(client_socket, SD_SEND);
            } else {
                read_sockets[i] = INVALID_SOCKET;
                closesocket(client_socket);
            }

            http_reader_destroy(reader);
        }

        SOCKET *socket_iter = read_sockets;
        SOCKET *valid_socket_iter = read_sockets;
        while (valid_socket_iter < read_sockets + read_socket_count) {
            if (*valid_socket_iter != INVALID_SOCKET) {
                *socket_iter = *valid_socket_iter;
                socket_iter += 1;
            }
            valid_socket_iter += 1;
        }
        read_socket_count = socket_iter - read_sockets;

        if (FD_ISSET(listen_socket, &read_sockets_set)) {
            SOCKET client_socket = accept(listen_socket, 0, 0);

            if (read_socket_count == FD_SETSIZE) {
                closesocket(client_socket);
                continue;
            }

            read_sockets[read_socket_count++] = client_socket;
        }
    }

    return 0;
}
