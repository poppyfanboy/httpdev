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

typedef enum {
    DIRECTORY_NOTIFIER,
    LISTEN_SOCKET,
    CLIENT_SOCKET,
} EventSourceKind;

typedef struct {
    HANDLE event;
    HANDLE directory;
    void *buffer;
    DWORD buffer_size;
    OVERLAPPED overlapped;
} DirectoryNotifier;

typedef struct {
    HANDLE event;
    SOCKET socket;
} ListenSocket;

typedef struct {
    HANDLE event;
    SOCKET socket;
    SocketProtocol protocol;
    bool closed;
} ClientSocket;

typedef struct {
    EventSourceKind kind;
    union {
        struct {
            HANDLE event;
        } generic;
        DirectoryNotifier directory_notifier;
        ListenSocket listen_socket;
        ClientSocket client_socket;
    } as;
} EventSource;

bool event_source_directory_notifier(WCHAR *directory_path, EventSource *event_source) {
    event_source->kind = DIRECTORY_NOTIFIER;
    DirectoryNotifier *directory_notifier = &event_source->as.directory_notifier;

    // Use FILE_FLAG_OVERLAPPED, so that ReadDirectoryChangesW is non-blocking.
    directory_notifier->directory = CreateFileW(
        directory_path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );
    if (directory_notifier->directory == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Some arbitrary large buffer size.
    directory_notifier->buffer_size = 256 * 1024;
    directory_notifier->buffer = malloc(directory_notifier->buffer_size);

    directory_notifier->overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    directory_notifier->event = directory_notifier->overlapped.hEvent;
    if (directory_notifier->event == INVALID_HANDLE_VALUE) {
        return false;
    }

    BOOL directory_changes_result = ReadDirectoryChangesW(
        directory_notifier->directory,
        directory_notifier->buffer, directory_notifier->buffer_size,
        TRUE,
        FILE_NOTIFY_CHANGE_LAST_WRITE,
        NULL,
        &directory_notifier->overlapped,
        NULL
    );
    if (directory_changes_result == 0) {
        return false;
    }

    return true;
}

bool event_source_listen_socket(char const *port, EventSource *event_source) {
    event_source->kind = LISTEN_SOCKET;
    ListenSocket *listen_socket = &event_source->as.listen_socket;

    struct addrinfo *address_info;
    struct addrinfo address_info_hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
        .ai_flags = AI_PASSIVE,
    };
    if (getaddrinfo(NULL, port, &address_info_hints, &address_info) != 0) {
        return false;
    }

    listen_socket->socket = socket(
        address_info->ai_family,
        address_info->ai_socktype,
        address_info->ai_protocol
    );
    if (bind(listen_socket->socket, address_info->ai_addr, (int)address_info->ai_addrlen) != 0) {
        return 1;
    }

    listen(listen_socket->socket, SOMAXCONN);

    listen_socket->event = WSACreateEvent();
    if (listen_socket->event == INVALID_HANDLE_VALUE) {
        return false;
    }
    WSAEventSelect(listen_socket->socket, listen_socket->event, FD_ACCEPT);

    return true;
}

bool event_source_client_socket(SOCKET socket, EventSource *event_source) {
    event_source->kind = CLIENT_SOCKET;
    ClientSocket *client_socket = &event_source->as.client_socket;

    client_socket->protocol = HTTP;
    client_socket->socket = socket;
    client_socket->closed = false;

    client_socket->event = WSACreateEvent();
    if (client_socket->event == INVALID_HANDLE_VALUE) {
        return false;
    }
    WSAEventSelect(socket, client_socket->event, FD_READ | FD_CLOSE);

    return true;
}

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

char *http_response_string(StringView content, char const *mime_type, isize *response_size) {
    char headers_format[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: %td\r\n"
        "Content-Type: %s\r\n"
        "\r\n";
    isize headers_size = snprintf(
        NULL, 0, headers_format,
        /* Content-Length: */ content.size,
        /* Content-Type: */ mime_type
    );

    char *response = malloc((headers_size + 1) + content.size);
    snprintf(
        response, headers_size + 1, headers_format,
        /* Content-Length: */ content.size,
        /* Content-Type: */ mime_type
    );
    memcpy(response + headers_size, content.data, content.size);

    *response_size = headers_size + content.size;
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

isize wide_string_length(WCHAR *string) {
    WCHAR *string_iter = string;
    while (*string_iter != L'\0') {
        string_iter += 1;
    }
    return string_iter - string;
}

int wmain(int arg_count, WCHAR **args) {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return 1;
    }

    WCHAR *directory_path = L"./";
    if (arg_count > 1) {
        directory_path = args[1];
    }

    struct {
        EventSource *data;
        isize count;
        isize capacity;
    } event_sources = {malloc(64 * sizeof(EventSource)), 0, 64};

    bool directory_notifier_created =
        event_source_directory_notifier(directory_path, &event_sources.data[event_sources.count]);
    event_sources.count += 1;

    bool listen_socket_created =
        event_source_listen_socket(PORT, &event_sources.data[event_sources.count]);
    event_sources.count += 1;

    if (!directory_notifier_created || !listen_socket_created) {
        return 1;
    }

    HANDLE *events = malloc(event_sources.capacity * sizeof(HANDLE));
    for (isize i = 0; i < event_sources.count; i += 1) {
        events[i] = event_sources.data[i].as.generic.event;
    }

    struct {
        char *data;
        isize size;
        isize capacity;
    } input = {malloc(IO_BUFFER_SIZE), 0, IO_BUFFER_SIZE};

    while (true) {
        DWORD wait_result = WaitForMultipleObjects(event_sources.count, events, FALSE, INFINITE);
        if (wait_result == WAIT_FAILED || wait_result == WAIT_TIMEOUT) {
            return 1;
        }

        EventSource *event_source = &event_sources.data[wait_result - WAIT_OBJECT_0];

        if (event_source->kind == LISTEN_SOCKET) {
            ListenSocket *listen_socket = &event_source->as.listen_socket;

            SOCKET socket = accept(listen_socket->socket, 0, 0);

            EventSource client_socket;
            if (!event_source_client_socket(socket, &client_socket)) {
                return 1;
            }

            if (event_sources.count < event_sources.capacity) {
                event_sources.data[event_sources.count] = client_socket;
                events[event_sources.count] = client_socket.as.generic.event;
                event_sources.count += 1;
            } else {
                closesocket(socket);
            }

            WSAResetEvent(listen_socket->event);
            continue;
        }

        if (event_source->kind == DIRECTORY_NOTIFIER) {
            DirectoryNotifier *directory_notifier = &event_source->as.directory_notifier;

            DWORD overlapped_bytes;
            BOOL overlapped_result = GetOverlappedResult(
                directory_notifier->directory,
                &directory_notifier->overlapped,
                &overlapped_bytes,
                FALSE
            );
            if (overlapped_result == FALSE) {
                return 1;
            }

            BOOL directory_changes_result = ReadDirectoryChangesW(
                directory_notifier->directory,
                directory_notifier->buffer, directory_notifier->buffer_size,
                TRUE,
                FILE_NOTIFY_CHANGE_LAST_WRITE,
                NULL,
                &directory_notifier->overlapped,
                NULL
            );
            if (directory_changes_result == 0) {
                return false;
            }

            FILE_NOTIFY_INFORMATION *notification = directory_notifier->buffer;
            while (true) {
                WCHAR path[MAX_PATH] = {0};
                memcpy(path, notification->FileName, notification->FileNameLength);

                DWORD path_attributes = GetFileAttributesW(path);
                if (
                    (path_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
                    (notification->Action & FILE_ACTION_MODIFIED) != 0
                ) {
                    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
                    WriteConsoleW(console, L"File update: ", 14, NULL, NULL);
                    WriteConsoleW(console, path, wide_string_length(path), NULL, NULL);
                    WriteConsoleW(console, L"\n", 1, NULL, NULL);

                    for (isize i = 0; i < event_sources.count; i += 1) {
                        if (
                            event_sources.data[i].kind == CLIENT_SOCKET &&
                            event_sources.data[i].as.client_socket.protocol == WEBSOCKET
                        ) {
                            ClientSocket *client_socket = &event_sources.data[i].as.client_socket;
                            assert(!client_socket->closed);
                            // https://www.rfc-editor.org/rfc/rfc6455.html#section-5.7
                            char message[] = {0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f};
                            if (!socket_send_all(client_socket->socket, message, sizeof(message))) {
                                client_socket->closed = true;
                                closesocket(client_socket->socket);
                            }
                        }
                    }
                }

                if (notification->NextEntryOffset == 0) {
                    break;
                }
                notification = (void *)((char *)notification + notification->NextEntryOffset);
            }

            continue;
        }

        if (event_source->kind == CLIENT_SOCKET) {
            ClientSocket *client_socket = &event_source->as.client_socket;

            if (client_socket->protocol == WEBSOCKET) {
                int bytes_received = recv(client_socket->socket, input.data, input.capacity, 0);

                if (bytes_received == 0 || bytes_received == SOCKET_ERROR) {
                    int error = WSAGetLastError();

                    // Ignore this error.
                    if (error != WSAEWOULDBLOCK) {
                        client_socket->closed = true;
                        closesocket(client_socket->socket);
                    }
                }

                // The client shall not speek to the server.
                // (Even if you don't call websocket.send() explicitly from JavaScript it might
                // still send a Close frame automatically which at least needs to be recv-ed.)
                if (bytes_received > 0) {
                    client_socket->closed = true;
                    closesocket(client_socket->socket);
                }
            }

            if (client_socket->protocol == HTTP) {
                HttpReader *reader = http_reader_create();
                input.size = 0;

                while (!http_reader_done(reader)) {
                    int bytes_received = recv(
                        client_socket->socket,
                        input.data + input.size, input.capacity - input.size,
                        0
                    );
                    if (bytes_received == 0) {
                        if (reader->state != HTTP_READ_FINISH) {
                            client_socket->closed = true;
                            closesocket(client_socket->socket);
                        }
                        break;
                    }
                    if (bytes_received == SOCKET_ERROR) {
                        client_socket->closed = true;
                        closesocket(client_socket->socket);
                        break;
                    }

                    input.size += bytes_received;
                    isize bytes_read = http_reader_feed(reader, input.data, input.size);

                    memmove(input.data, input.data + bytes_read, input.size - bytes_read);
                    input.size -= bytes_read;
                }

                if (!client_socket->closed && reader->is_websocket) {
                    client_socket->protocol = WEBSOCKET;

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

                    if (!socket_send_all(client_socket->socket, response, response_size)) {
                        client_socket->closed = true;
                        closesocket(client_socket->socket);
                    }

                    free(accept_key);
                    free(response);
                }

                if (!client_socket->closed && !reader->is_websocket) {
                    char *response = NULL;
                    isize response_size = 0;

                    if (string_equals(reader->request_line.uri, SV("/"))) {
                        response = http_response_file(
                            SV("index.html"),
                            &response_size
                        );
                    }

                    if (string_equals(reader->request_line.uri, SV("/hot-reload.js"))) {
                        response = http_response_string(
                            SV(
                                "const socket = new WebSocket('ws://localhost:8080/');\n"
                                "socket.addEventListener('message', (event) => {\n"
                                "    location.reload();\n"
                                "});"
                            ),
                            "application/javascript",
                            &response_size
                        );
                    }

                    if (response == NULL) {
                        response = http_response_404(&response_size);
                    }

                    if (!socket_send_all(client_socket->socket, response, response_size)) {
                        client_socket->closed = true;
                        closesocket(client_socket->socket);
                    }
                    free(response);

                    // https://blog.netherlabs.nl/articles/2009/01/18/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable
                    //
                    // First shutdown the socket, then wait for the client to close it (select()
                    // will detect a read update on this socket later). This still does not
                    // guarantee that the client will receive every single byte, but I don't know
                    // what else can I do.
                    shutdown(client_socket->socket, SD_SEND);
                }

                http_reader_destroy(reader);
            }

            if (client_socket->closed) {
                isize removed_index = wait_result - WAIT_OBJECT_0;

                WSACloseEvent(events[removed_index]);

                event_sources.data[removed_index] = event_sources.data[event_sources.count - 1];
                events[removed_index] = events[event_sources.count - 1];
                event_sources.count -= 1;
            }

            continue;
        }

        assert(false);
        return 1;
    }

    return 0;
}
