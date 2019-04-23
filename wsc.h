#pragma once

#include <stdbool.h>
#include <wslay/wslay.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "esp_tls.h"

typedef struct wsc_s wsc_t;
typedef struct wsc_headers_s wsc_headers_t;
typedef struct wsc_header_s wsc_header_t;

typedef struct wslay_event_msg wsc_msg_t;

typedef void (*wsc_msg_callback)(wsc_t *wsc, const struct wslay_event_on_msg_recv_arg *msg);

typedef enum {
    WSC_OK = 0,
    WSC_ERR_UNKNOWN,
    WSC_ERR_NOMEM,
    WSC_ERR_HANDSHAKE_NOMEM,
    WSC_ERR_HANDSHAKE_ADDRINFO,
    WSC_ERR_HANDSHAKE_NO_ADDRESS,
    WSC_ERR_CREATE_SOCKET,
    WSC_ERR_CONNECT,
    WSC_ERR_HANDSHAKE_WRITE,
    WSC_ERR_HANDSHAKE_CREATE_KEY,
    WSC_ERR_HANDSHAKE_ACCEPT_KEY_SHA1,
    WSC_ERR_HANDSHAKE_ACCEPT_KEY_BASE64,
    WSC_ERR_HANDSHAKE_RESPONSE_TOO_LONG,
    WSC_ERR_HANDSHAKE_SELECT,
    WSC_ERR_HANDSHAKE_TIMEOUT,
    WSC_ERR_HANDSHAKE_READ,
    WSC_ERR_HANDSHAKE_EOF,
    WSC_ERR_HANDSHAKE_INVALID_RESPONSE,
    WSC_ERR_HANDSHAKE_INVALID_STATUS,
    WSC_ERR_HANDSHAKE_INVALID_HEADERS,
    WSC_ERR_HANDSHAKE_ACCEPT_KEY_MISMATCH,
    WSC_ERR_SET_SOCKETOPT,
    WSC_ERR_SELECT,
    WSC_ERR_RECV,
    WSC_ERR_SEND_QUEUE_FULL,
    WSC_ERR_SHUTDOWN_QUEUE_FULL,
} wsc_err_code;

struct wsc_s {
    int fd;
    esp_tls_t *tls;
    wslay_event_context_ptr ctx;
    struct wslay_event_callbacks cb;
    QueueHandle_t shutdown_queue;
    QueueHandle_t send_queue;
    QueueHandle_t recv_queue;
    wsc_msg_callback msg_callback;
};

struct wsc_headers_s {
    size_t num_headers;
    void *headers;
};

struct wsc_header_s {
    const char *key;
    const char *value;
};

wsc_err_code wsc_init(wsc_t *w);
void wsc_close(wsc_t *w);

wsc_headers_t *wsc_headers_new(size_t max_headers);
void wsc_headers_free(wsc_headers_t *headers);
void wsc_headers_add(wsc_headers_t *headers, const char *key, const char *value);

wsc_err_code wsc_connect(wsc_t *wsc, const char *host, uint16_t port, const char *path,
                         wsc_headers_t *headers, esp_tls_cfg_t *tls_cfg);

wsc_err_code wsc_shutdown(wsc_t *wsc);
wsc_err_code wsc_send(wsc_t *wsc, wsc_msg_t *msg);

wsc_err_code wsc_run(wsc_t *wsc);
