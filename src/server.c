#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <string.h> // memcpy, memmove
#include <stdlib.h> // malloc, free
#include <stdio.h>  // fopen, fread, fclose, fseek, ftell, fprintf, stderr
#include <stdlib.h> // abort

#define DEFAULT_PORT "8080"
#define MAX_SERVER_EVENTS 64
#define IO_BUFFER_CAPACITY 4096

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

    // Some arbitrarily large buffer size.
    directory_notifier->buffer_size = 256 * 1024;
    directory_notifier->buffer = malloc(directory_notifier->buffer_size);

    directory_notifier->overlapped.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    directory_notifier->event = directory_notifier->overlapped.hEvent;

    BOOL directory_changes_result = ReadDirectoryChangesW(
        directory_notifier->directory,
        directory_notifier->buffer, directory_notifier->buffer_size,
        TRUE,
        FILE_NOTIFY_CHANGE_LAST_WRITE,
        NULL,
        &directory_notifier->overlapped,
        NULL
    );
    if (directory_changes_result == FALSE) {
        return false;
    }

    return true;
}

bool directory_files_changed(DirectoryNotifier *directory_notifier) {
    DWORD overlapped_bytes;
    BOOL overlapped_result = GetOverlappedResult(
        directory_notifier->directory,
        &directory_notifier->overlapped,
        &overlapped_bytes,
        FALSE
    );
    if (overlapped_result == FALSE) {
        abort();
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
    if (directory_changes_result == FALSE) {
        abort();
    }

    FILE_NOTIFY_INFORMATION *notification = directory_notifier->buffer;
    while (true) {
        // Make sure the file name is null-terminated.
        WCHAR path[MAX_PATH] = {0};
        memcpy(path, notification->FileName, notification->FileNameLength);

        bool path_is_file = (GetFileAttributesW(path) & FILE_ATTRIBUTE_DIRECTORY) == 0;
        if (path_is_file && (notification->Action & FILE_ACTION_MODIFIED) != 0) {
            return true;
        }

        if (notification->NextEntryOffset == 0) {
            break;
        }
        notification = (FILE_NOTIFY_INFORMATION *)(
            (char *)notification + notification->NextEntryOffset
        );
    }

    return false;
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
    listen_socket->event = CreateEventW(NULL, FALSE, FALSE, NULL);

    if (bind(listen_socket->socket, address_info->ai_addr, (int)address_info->ai_addrlen) != 0) {
        return false;
    }

    listen(listen_socket->socket, SOMAXCONN);

    // This makes the socket non-blocking automatically.
    // We can drain it by calling accept() repeatedly with no fear of getting blocked.
    WSAEventSelect(listen_socket->socket, listen_socket->event, FD_ACCEPT);

    return true;
}

void event_source_client_socket(SOCKET socket, EventSource *event_source) {
    event_source->kind = CLIENT_SOCKET;
    ClientSocket *client_socket = &event_source->as.client_socket;

    client_socket->protocol = HTTP;
    client_socket->socket = socket;
    client_socket->event = CreateEventW(NULL, FALSE, FALSE, NULL);

    // This makes the socket non-blocking automatically...
    WSAEventSelect(socket, client_socket->event, FD_READ | FD_CLOSE);
    // ...so make it blocking, because we can't handle EWOULDBLOCK for client sockets (this would
    // require saving the current state of what was read or what was written and coming back to this
    // socket whenever an FD_READ or an FD_WRITE event occurs respectively):
    u_long make_non_blocking = 0;
    ioctlsocket(socket, FIONBIO, &make_non_blocking);
}

String http_response_404(void) {
    char response_data[] =
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 0\r\n\r\n";
    return string_clone(SV(response_data));
}

String http_response_file(StringView file_name) {
    FILE *file = fopen(file_name.data, "rb");
    if (file == NULL) {
        return http_response_404();
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

    String response = {0};
    string_reserve(&response, 256 + file_size);

    char headers_format[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: %td\r\n"
        "Content-Type: %s\r\n"
        "\r\n";
    string_append_format(
        &response, headers_format,
        /* Content-Length: */ file_size,
        /* Content-Type: */ mime_type
    );

    string_reserve(&response, response.size + file_size);
    while (true) {
        isize bytes_read = fread(
            response.data + response.size,
            1, response.capacity - response.size,
            file
        );

        if (bytes_read > 0) {
            response.size += bytes_read;
        } else {
            break;
        }
    }

    fclose(file);

    return response;
}

String http_response_string(StringView content, char const *mime_type) {
    String response = {0};
    string_reserve(&response, 256 + content.size);

    char headers_format[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: %td\r\n"
        "Content-Type: %s\r\n"
        "\r\n";
    string_append_format(
        &response, headers_format,
        /* Content-Length: */ content.size,
        /* Content-Type: */ mime_type
    );
    string_append(&response, content);

    return response;
}

bool socket_send_all(SOCKET socket, StringView response) {
    while (response.size > 0) {
        int bytes_sent = send(socket, response.data, response.size, 0);
        if (bytes_sent == 0 || bytes_sent == SOCKET_ERROR) {
            return false;
        }

        response.data += bytes_sent;
        response.size -= bytes_sent;
    }

    return true;
}

typedef struct {
    HANDLE *events;
    EventSource *event_sources;
    isize event_count;

    char *buffer;
    isize buffer_used;
} Server;

void server_accept_clients(Server *server, SOCKET listen_socket) {
    // Accept and close any sockets we cannot accept at the moment.
    if (server->event_count == MAX_SERVER_EVENTS) {
        while (true) {
            SOCKET socket = accept(listen_socket, NULL, NULL);
            if (socket != SOCKET_ERROR) {
                closesocket(socket);
            } else {
                return;
            }
        }
    }

    while (true) {
        SOCKET socket = accept(listen_socket, NULL, NULL);
        if (socket == SOCKET_ERROR) {
            int error = WSAGetLastError();

            if (error == WSAEWOULDBLOCK) {
                break;
            }
            if (error != WSAEWOULDBLOCK) {
                abort();
            }
        }

        EventSource client_socket;
        event_source_client_socket(socket, &client_socket);

        server->event_sources[server->event_count] = client_socket;
        server->events[server->event_count] = client_socket.as.generic.event;
        server->event_count += 1;
    }
}

void server_broadcast(Server *server, StringView message) {
    for (isize i = 0; i < server->event_count; i += 1) {
        if (server->event_sources[i].kind != CLIENT_SOCKET) {
            continue;
        }
        ClientSocket *client_socket = &server->event_sources[i].as.client_socket;

        if (client_socket->protocol == WEBSOCKET) {
            socket_send_all(client_socket->socket, message);
        }
    }
}

String server_http_response(Server *server, SOCKET client_socket, bool *upgraded_to_websocket) {
    HttpReader *reader = http_reader_create();
    server->buffer_used = 0;

    while (!http_reader_done(reader)) {
        int bytes_received = recv(
            client_socket,
            server->buffer + server->buffer_used, IO_BUFFER_CAPACITY - server->buffer_used,
            0
        );
        if (bytes_received == 0 || bytes_received == SOCKET_ERROR) {
            break;
        }

        server->buffer_used += bytes_received;
        isize bytes_read = http_reader_feed(reader, server->buffer, server->buffer_used);

        memmove(
            server->buffer,
            server->buffer + bytes_read, server->buffer_used - bytes_read
        );
        server->buffer_used -= bytes_read;
    }

    *upgraded_to_websocket = reader->is_websocket;

    if (reader->is_websocket) {
        string_append(&reader->websocket_key, SV("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));

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
        String response = {0};
        string_append_format(&response, response_format, accept_key);
        free(accept_key);

        http_reader_destroy(reader);
        return response;
    }

    String response = string_empty();
    isize response_size = 0;

    if (string_equals(reader->request_line.uri, SV("/"))) {
        response = http_response_file(SV("index.html"));
    }

    if (string_equals(reader->request_line.uri, SV("/hot-reload.js"))) {
        char const code_format[] = SRC(
            const socket = new WebSocket("ws://localhost:%s/");
            socket.addEventListener("message", (event) => {
                location.reload();
            });
        );
        String code = {0};
        string_append_format(&code, code_format, DEFAULT_PORT);

        response = http_response_string(
            string_view(&code),
            "application/javascript"
        );

        string_destroy(&code);
    }

    if (response.size == 0) {
        response = http_response_404();
    }

    http_reader_destroy(reader);
    return response;
}

int wmain(int arg_count, WCHAR **args) {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        fprintf(stderr, "Failed to initialize winsock version 2.2\n");
        abort();
    }

    WCHAR *directory_path = L"./";
    if (arg_count > 1) {
        directory_path = args[1];
    }

    Server server = {
        .events = malloc(MAX_SERVER_EVENTS * sizeof(HANDLE)),
        .event_sources = malloc(MAX_SERVER_EVENTS * sizeof(EventSource)),
        .buffer = malloc(IO_BUFFER_CAPACITY),
    };

    bool directory_notifier_created = event_source_directory_notifier(
        directory_path,
        &server.event_sources[0]
    );
    if (!directory_notifier_created) {
        fprintf(stderr, "Failed to initialize a directory watcher\n");
        abort();
    }
    server.events[0] = server.event_sources[0].as.generic.event;
    server.event_count = 1;

    bool listen_socket_created = event_source_listen_socket(
        DEFAULT_PORT,
        &server.event_sources[1]
    );
    if (!listen_socket_created) {
        fprintf(stderr, "Failed to start a server\n");
        abort();
    }
    server.events[1] = server.event_sources[1].as.generic.event;
    server.event_count = 2;

    while (true) {
        DWORD wait_result = WaitForMultipleObjects(
            server.event_count, server.events, FALSE,
            INFINITE
        );
        if (wait_result == WAIT_FAILED) {
            abort();
        }
        EventSource *event_source = &server.event_sources[wait_result - WAIT_OBJECT_0];

        if (event_source->kind == LISTEN_SOCKET) {
            ListenSocket *listen_socket = &event_source->as.listen_socket;
            server_accept_clients(&server, listen_socket->socket);

            continue;
        }

        if (event_source->kind == DIRECTORY_NOTIFIER) {
            DirectoryNotifier *directory_notifier = &event_source->as.directory_notifier;
            if (directory_files_changed(directory_notifier)) {
                // https://www.rfc-editor.org/rfc/rfc6455.html#section-5.7
                char message_data[] = {0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f};

                StringView message = {message_data, sizeof(message_data)};
                server_broadcast(&server, message);
            }

            continue;
        }

        if (event_source->kind == CLIENT_SOCKET) {
            ClientSocket *client_socket = &event_source->as.client_socket;

            WSANETWORKEVENTS socket_events = {0};
            WSAEnumNetworkEvents(client_socket->socket, client_socket->event, &socket_events);

            bool client_socket_closed =
                (socket_events.lNetworkEvents & FD_CLOSE) != 0 ||
                socket_events.iErrorCode[FD_READ_BIT]     != 0 ||
                socket_events.iErrorCode[FD_CLOSE_BIT]    != 0;

            bool client_socket_readable =
                !client_socket_closed &&
                (socket_events.lNetworkEvents & FD_READ) != 0;

            if (client_socket_readable && client_socket->protocol == WEBSOCKET) {
                isize total_bytes_received = 0;
                while (true) {
                    int bytes_received = recv(
                        client_socket->socket,
                        server.buffer, IO_BUFFER_CAPACITY,
                        0
                    );
                    if (bytes_received == 0 || bytes_received == SOCKET_ERROR) {
                        break;
                    }
                    total_bytes_received += bytes_received;
                }

                // The client shall not speek to the server.
                // (Even if you don't call websocket.send() explicitly from JavaScript it might
                // still send a Close frame automatically which at least needs to be recv-ed.)
                if (total_bytes_received > 0) {
                    // https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2
                    char close_frame_data[] = {0x88, 0x00};

                    // Send the close frame, otherwise the browser will delay WebSocket connection
                    // after hot-reloading the page for some reason.
                    StringView close_frame = {close_frame_data, sizeof(close_frame_data)};
                    socket_send_all(client_socket->socket, close_frame);

                    shutdown(client_socket->socket, SD_SEND);
                }
            }

            if (client_socket_readable && client_socket->protocol == HTTP) {
                bool upgraded_to_websocket;

                String response = server_http_response(
                    &server,
                    client_socket->socket,
                    &upgraded_to_websocket
                );
                socket_send_all(client_socket->socket, string_view(&response));
                string_destroy(&response);

                if (upgraded_to_websocket) {
                    client_socket->protocol = WEBSOCKET;
                } else {
                    // https://blog.netherlabs.nl/articles/2009/01/18/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable
                    //
                    // First shutdown the socket, then wait for the client to close it (select()
                    // will detect a read update on this socket later). This still does not
                    // guarantee that the client will receive every single byte, but I don't know
                    // what else can I do.
                    shutdown(client_socket->socket, SD_SEND);
                }
            }

            if (client_socket_closed) {
                isize removed_index = wait_result - WAIT_OBJECT_0;

                CloseHandle(server.events[removed_index]);
                closesocket(client_socket->socket);

                server.event_sources[removed_index] = server.event_sources[server.event_count - 1];
                server.events[removed_index] = server.events[server.event_count - 1];
                server.event_count -= 1;
            }

            continue;
        }
    }

    return 0;
}
