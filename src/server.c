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
#include "base64.c"
#include "sha1.c"

typedef enum {
    HTTP,
    WEBSOCKET,
} SocketProtocol;

typedef struct {
    SOCKET socket;
    SocketProtocol protocol;
    bool closed;
    bool has_error;
} Socket;

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
        "Content-Type: %s\r\n"
        "\r\n";

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

bool socket_send_all(SOCKET socket, char const *data, isize data_size) {
    while (data_size > 0) {
        int bytes_sent = send(socket, data, data_size, 0);
        if (bytes_sent == 0 || bytes_sent == SOCKET_ERROR) {
            return false;
        }

        data += bytes_sent;
        data_size -= bytes_sent;
    }

    return true;
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

    Socket read_sockets[FD_SETSIZE] = {0};

    isize read_socket_count = 1;
    read_sockets[0] = (Socket){
        .protocol = HTTP,
        .socket = listen_socket,
        .closed = false,
        .has_error = false,
    };

    struct {
        char *data;
        isize size;
        isize capacity;
    } input = {malloc(IO_BUFFER_SIZE), 0, IO_BUFFER_SIZE};

    while (true) {
        fd_set read_sockets_set, error_sockets_set;
        FD_ZERO(&read_sockets_set);
        FD_ZERO(&error_sockets_set);
        for (isize i = 0; i < read_socket_count; i += 1) {
            FD_SET(read_sockets[i].socket, &read_sockets_set);
            FD_SET(read_sockets[i].socket, &error_sockets_set);
        }
        select(0, &read_sockets_set, NULL, &error_sockets_set, NULL);

        for (isize i = 0; i < read_socket_count; i += 1) {
            if (read_sockets[i].socket == listen_socket) {
                continue;
            }

            Socket *client = &read_sockets[i];

            if (!FD_ISSET(client->socket, &read_sockets_set)) {
                continue;
            }
            if (FD_ISSET(client->socket, &error_sockets_set)) {
                client->has_error = true;
                client->closed = true;
                closesocket(client->socket);
                continue;
            }

            if (client->protocol == WEBSOCKET) {
                int bytes_received = recv(client->socket, input.data, input.capacity, 0);
                if (bytes_received == 0 || bytes_received == SOCKET_ERROR) {
                    client->closed = true;
                    closesocket(client->socket);
                }

                // The client shall not speek to the server.
                // (Even if you don't call websocket.send() explicitly from JavaScript it might
                // still send a Close frame automatically which at least needs to be recv-ed.)
                if (bytes_received > 0) {
                    client->closed = true;
                    closesocket(client->socket);
                }

                continue;
            }

            HttpReader *reader = http_reader_create();
            input.size = 0;

            while (!http_reader_done(reader)) {
                int bytes_received = recv(
                    client->socket,
                    input.data + input.size, input.capacity - input.size,
                    0
                );
                if (bytes_received == 0) {
                    break;
                }
                if (bytes_received == SOCKET_ERROR) {
                    client->has_error = true;
                    break;
                }

                input.size += bytes_received;
                isize bytes_read = http_reader_feed(reader, input.data, input.size);

                memmove(input.data, input.data + bytes_read, input.size - bytes_read);
                input.size -= bytes_read;
            }

            if (client->has_error || reader->state != HTTP_READ_FINISH) {
                client->closed = true;
                closesocket(client->socket);
            } else {
                // https://www.rfc-editor.org/rfc/rfc6455.html#section-4.2.2
                if (reader->is_websocket) {
                    read_sockets[i].protocol = WEBSOCKET;

                    string_append(
                        &reader->websocket_key,
                        SV("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
                    );

                    u32 hash[5];
                    sha1((u8 *)reader->websocket_key.data, reader->websocket_key.size, hash);

                    // Re-order to big-endian.
                    u8 hash_bytes[sizeof(hash)];
                    for (isize i = 0; i < countof(hash); i += 1) {
                        hash_bytes[4 * i + 0] = (hash[i] >> 24) & 0xff;
                        hash_bytes[4 * i + 1] = (hash[i] >> 16) & 0xff;
                        hash_bytes[4 * i + 2] = (hash[i] >>  8) & 0xff;
                        hash_bytes[4 * i + 3] = (hash[i] >>  0) & 0xff;
                    }

                    isize accept_size = base64_encode(hash_bytes, sizeof(hash_bytes), NULL);
                    char *accept_key = malloc(accept_size + 1);
                    memset(accept_key, 0, accept_size + 1);
                    base64_encode(hash_bytes, sizeof(hash_bytes), accept_key);

                    char response_format[] =
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: %s\r\n"
                        "\r\n";
                    isize response_size = snprintf(NULL, 0, response_format, accept_key);
                    char *response = malloc(response_size + 1);
                    snprintf(response, response_size + 1, response_format, accept_key);

                    if (!socket_send_all(client->socket, response, response_size)) {
                        client->has_error = true;
                    }

                    free(accept_key);
                    free(response);
                }

                if (!reader->is_websocket) {
                    char *response = NULL;
                    isize response_size = 0;

                    if (string_equals(reader->request_line.uri, SV("/"))) {
                        response = http_response_file(SV("index.html"), &response_size);
                    }

                    if (response == NULL) {
                        response = http_response_404(&response_size);
                    }

                    if (!socket_send_all(client->socket, response, response_size)) {
                        client->has_error = true;
                    }
                    free(response);

                    // https://blog.netherlabs.nl/articles/2009/01/18/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable
                    //
                    // First shutdown the socket, then wait for the client to close it (select()
                    // will detect a read update on this socket later). This still does not
                    // guarantee that the client will receive every single byte, but I don't know
                    // what else can I do.
                    shutdown(client->socket, SD_SEND);
                }
            }

            http_reader_destroy(reader);
        }

        Socket *socket_iter = read_sockets;
        Socket *alive_socket_iter = read_sockets;
        while (alive_socket_iter < read_sockets + read_socket_count) {
            if (!alive_socket_iter->closed && !alive_socket_iter->has_error) {
                *socket_iter = *alive_socket_iter;
                socket_iter += 1;
            }
            alive_socket_iter += 1;
        }
        read_socket_count = socket_iter - read_sockets;

        if (FD_ISSET(listen_socket, &read_sockets_set)) {
            SOCKET client_socket = accept(listen_socket, 0, 0);

            if (read_socket_count == FD_SETSIZE) {
                closesocket(client_socket);
                continue;
            }

            Socket client = {
                .socket = client_socket,
                .protocol = HTTP,
                .closed = false,
                .has_error = false,
            };
            read_sockets[read_socket_count] = client;
            read_socket_count += 1;
        }
    }

    return 0;
}
