#include "wsc.h"

#include <stdint.h>
#include <string.h>

#include "esp_log.h"
#include "esp_system.h"

#include "lwip/err.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha1.h"

#include "picohttpparser.h"

static const char *TAG = "wsc";

static const char *WS_MAGICNUMBER = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static ssize_t wsc_recv_internal(wsc_t *w, uint8_t *buf, size_t len, int flags)
{
    if (NULL != w->tls) {
        /* esp_tls or mbedtls doesn't have recv(2) interface */
        return esp_tls_conn_read(w->tls, buf, len);
    } else {
        return recv(w->fd, buf, len, flags);
    }
}

static ssize_t wsc_send_internal(wsc_t *w, const uint8_t *buf, size_t len, int flags)
{
    if (NULL != w->tls) {
        return esp_tls_conn_write(w->tls, buf, len);
    } else {
        return send(w->fd, buf, len, flags);
    }
}

static ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags,
                             void *user_data)
{
    wsc_t *wsc = (wsc_t *)user_data;
    while (true) {
        int r = wsc_recv_internal(wsc, buf, len, flags);
        if (r < 0) {
            if (NULL != wsc->tls) {
                if (r == MBEDTLS_ERR_SSL_WANT_READ) {
                    wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
                } else {
                    wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
                }
            } else {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
                } else {
                    wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
                }
            }
        } else if (0 == r) {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
            r = -1;
        }
        return r;
    }
    /* never reach here */
    return -1;
}

static ssize_t send_callback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len,
                             int flags, void *user_data)
{
    wsc_t *wsc = (wsc_t *)user_data;
    while (true) {
        int r = wsc_send_internal(wsc, data, len, flags);
        if (r < 0) {
            if (NULL != wsc->tls) {
                if (r == MBEDTLS_ERR_SSL_WANT_WRITE || r == MBEDTLS_ERR_SSL_WANT_READ) {
                    wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
                } else {
                    wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
                }
            } else {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
                } else {
                    wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
                }
            }
        } else if (0 == r) {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
            r = -1;
        }
        return r;
    }
    /* never reach */
    return -1;
}

static int genmask_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data)
{
    esp_fill_random(buf, len);
    return 0;
}

static void msg_callback(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg,
                         void *user_data)
{
    wsc_t *wsc = (wsc_t *)user_data;
    if (NULL != wsc->msg_callback) {
        wsc->msg_callback(wsc, arg);
    }
}

wsc_err_code wsc_init(wsc_t *w)
{
    memset(&w->cb, 0, sizeof(w->cb));
    w->cb.recv_callback = recv_callback;
    w->cb.send_callback = send_callback;
    w->cb.genmask_callback = genmask_callback;
    w->cb.on_msg_recv_callback = msg_callback;

    w->fd = -1;
    w->tls = NULL;

    w->shutdown_queue = xQueueCreate(1, sizeof(int));
    w->send_queue = xQueueCreate(10, sizeof(wsc_msg_t));
    w->recv_queue = xQueueCreate(1, sizeof(int));
    w->msg_callback = NULL;

    if (0 != wslay_event_context_client_init(&w->ctx, &w->cb, w)) {
        return WSC_ERR_NOMEM;
    }
    return WSC_OK;
}

void wsc_close(wsc_t *w)
{
    wslay_event_context_free(w->ctx);
    w->ctx = NULL;
    if (w->fd >= 0) {
        shutdown(w->fd, SHUT_WR);
        close(w->fd);
        w->fd = -1;
    }
    if (NULL != w->tls) {
        esp_tls_conn_delete(w->tls);
        w->tls = NULL;
    }
    memset(&w->cb, 0, sizeof(w->cb));
    vQueueDelete(w->shutdown_queue);
    vQueueDelete(w->send_queue);
    vQueueDelete(w->recv_queue);
}

wsc_headers_t *wsc_headers_new(size_t max_headers)
{
    wsc_headers_t *headers = malloc(sizeof(size_t) + sizeof(wsc_header_t) * max_headers);
    if (NULL == headers) {
        return NULL;
    }
    headers->num_headers = 0;
    return headers;
}

void wsc_headers_free(wsc_headers_t *headers)
{
    free(headers);
}

void wsc_headers_add(wsc_headers_t *headers, const char *key, const char *value)
{
    wsc_header_t *header = (wsc_header_t *)((uint8_t *)headers + offsetof(wsc_headers_t, headers));
    header[headers->num_headers++] = (wsc_header_t){key, value};
}

static wsc_err_code create_client_id(char *buf, size_t buf_len)
{
    uint8_t b[16];
    esp_fill_random(b, 16);
    size_t len;
    if (0 != mbedtls_base64_encode((uint8_t *)buf, buf_len - 1, &len, b, 16)) {
        ESP_LOGE(TAG, "failed to create client id, %u buffer length required, but have %u",
                 (uint32_t)len, (uint32_t)buf_len - 1);
        return WSC_ERR_HANDSHAKE_CREATE_KEY;
    }
    buf[len] = 0;
    return WSC_OK;
}

static wsc_err_code create_accept_key(const char *client_id, char *buf, size_t buf_len)
{
    char b[68];
    uint8_t sb[20];
    size_t len = snprintf(b, 64, "%s%s", (const char *)client_id, WS_MAGICNUMBER);
    if (0 != mbedtls_sha1_ret((const uint8_t *)b, len, sb)) {
        ESP_LOGE(TAG, "create_accept_key failed: sha1 error");
        return WSC_ERR_HANDSHAKE_ACCEPT_KEY_SHA1;
    }
    size_t r;
    if (0 != mbedtls_base64_encode((uint8_t *)buf, buf_len - 1, &r, sb, 20)) {
        ESP_LOGE(TAG, "failed to create accept_key, %u buffer length required, but have %u",
                 (uint32_t)r, (uint32_t)buf_len - 1);
        return WSC_ERR_HANDSHAKE_ACCEPT_KEY_BASE64;
    }
    buf[r] = 0;
    return WSC_OK;
}

static int handshake_write(wsc_t *w, const char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t r = wsc_send_internal(w, (const uint8_t *)buf + off, len - off, 0);
        if (-1 == r) {
            if (errno == EINTR) {
                continue;
            }
            ESP_LOGE(TAG, "handshake write error: %d", errno);
            return -1;
        }
        off += r;
    }
    return off;
}

static ssize_t handshake_read(wsc_t *w, char *buf, size_t buf_len, const char *client_key)
{
    struct timeval tv = {
        .tv_sec = 10,
        .tv_usec = 0,
    };
    fd_set rfds;

    int pret, minor_version, status;
    struct phr_header headers[32];
    const char *body;
    size_t body_len;

    size_t off = 0;
    size_t len = buf_len - 1; /* -1 for excluding null terminate */
    while (true) {
        if (off >= len) {
            ESP_LOGE(TAG, "handshake_read: response is too long");
            return -WSC_ERR_HANDSHAKE_RESPONSE_TOO_LONG;
        }

        int fd = NULL != w->tls ? w->tls->sockfd : w->fd;

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        int s = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (s < 0) {
            ESP_LOGE(TAG, "handshake_read error: select failed");
            return -WSC_ERR_HANDSHAKE_SELECT;
        } else if (0 == s) {
            ESP_LOGE(TAG, "handshake timeout");
            return -WSC_ERR_HANDSHAKE_TIMEOUT;
        } else {
            ssize_t r = wsc_recv_internal(w, (uint8_t *)buf + off, len, 0);
            if (-1 == r) {
                if (errno == EINTR) {
                    continue;
                }
                ESP_LOGE(TAG, "handshake_read error: %d", errno);
                return -WSC_ERR_HANDSHAKE_READ;
            } else if (0 == r) {
                ESP_LOGE(TAG, "handshake_read error: unexpected eof");
                return -WSC_ERR_HANDSHAKE_EOF;
            }

            size_t num_headers = sizeof(headers) / sizeof(headers[0]);
            pret = phr_parse_response(buf, off + r, &minor_version, &status, &body, &body_len,
                                      headers, &num_headers, off);

            off += r;
            buf[off] = 0;

            if (-1 == pret) {
                ESP_LOGE(TAG, "handshake_read error: invalid response");
                return -WSC_ERR_HANDSHAKE_INVALID_RESPONSE;
            } else if (pret > 0) {
                /* parse done */
                if (status != 101) {
                    ESP_LOGE(TAG, "handshake_read error: invalid response status");
                    return -WSC_ERR_HANDSHAKE_INVALID_STATUS;
                }
                bool upgrade_ok[2] = {false, false};
                bool accept_ok = false;
                for (int i = 0; i < num_headers; i++) {
                    if (0 == strncasecmp(headers[i].name, "Upgrade", headers[i].name_len)) {
                        if (headers[i].value_len > 0 &&
                            0 == strncmp(headers[i].value, "websocket", headers[i].value_len)) {
                            upgrade_ok[0] = true;
                        }
                    } else if (0 ==
                               strncasecmp(headers[i].name, "Connection", headers[i].name_len)) {
                        if (headers[i].value_len > 0 &&
                            0 == strncmp(headers[i].value, "Upgrade", headers[i].value_len)) {
                            upgrade_ok[1] = true;
                        }
                    } else if (0 == strncasecmp(headers[i].name, "Sec-WebSocket-Accept",
                                                headers[i].name_len)) {
                        char accept_key[40];
                        if (0 != create_accept_key(client_key, accept_key, 40)) {
                            ESP_LOGE(TAG, "handshake_read error: failed to create accept_key");
                            return -1;
                        }
                        if (headers[i].value_len > 0 &&
                            0 == strncmp(headers[i].value, accept_key, headers[i].value_len)) {
                            accept_ok = true;
                        }
                    }
                }
                if (!upgrade_ok[0] || !upgrade_ok[1]) {
                    ESP_LOGE(TAG, "handshake_read error: invalid response header");
                    return -WSC_ERR_HANDSHAKE_INVALID_HEADERS;
                }
                if (!accept_ok) {
                    ESP_LOGE(TAG, "handshake_read error: invalid accept key");
                    return -WSC_ERR_HANDSHAKE_ACCEPT_KEY_MISMATCH;
                }
                return off;
            }
        }
    }
    /* never reach heare */
    return -WSC_ERR_UNKNOWN;
}

static wsc_err_code wsc_handshake(wsc_t *wsc, const char *host, uint16_t port, const char *path,
                                  wsc_headers_t *headers)
{
    wsc_err_code err;
    char client_id[32];

    err = create_client_id(client_id, 32);
    if (WSC_OK != err) {
        return err;
    }
    ESP_LOGD(TAG, "client_id generated: %s", client_id);

    /* base template, 127byte exclude %s
    "GET %s HTTP/1.1\r\n"
        "Host: %s:%s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
    */
    size_t req_len = 128 + strlen(path) + strlen(host) + 1 +
                     5 /* host:port, :port may be truncated but no care */
                     + strlen((char *)client_id);
    if (NULL != headers) {
        wsc_header_t *h = (wsc_header_t *)((uint8_t *)headers + offsetof(wsc_headers_t, headers));
        for (int i = 0; i < headers->num_headers; i++) {
            req_len += strlen((h + i)->key) + 2 + strlen((h + i)->value) + 2;
        }
    }
    char *req = malloc(req_len);
    if (NULL == req) {
        ESP_LOGE(TAG, "malloc failed");
        return WSC_ERR_HANDSHAKE_NOMEM;
    }

    int r;
    if ((NULL == wsc->tls && 80 == port) || (NULL != wsc->tls && 443 == port)) {
        r = snprintf(req, req_len,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n",
                     path, host, client_id);
    } else {
        r = snprintf(req, req_len,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s:%u\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n",
                     path, host, port, client_id);
    }
    if (NULL != headers) {
        wsc_header_t *h = (wsc_header_t *)((uint8_t *)headers + offsetof(wsc_headers_t, headers));
        for (int i = 0; i < headers->num_headers; i++) {
            r += snprintf(req + r, req_len - r, "%s: %s\r\n", (h + i)->key, (h + i)->value);
        }
    }
    r += snprintf(req + r, req_len - r, "\r\n");

    if (-1 == handshake_write(wsc, req, r)) {
        free(req);
        return WSC_ERR_HANDSHAKE_WRITE;
    }

    char res[512];
    size_t res_len = handshake_read(wsc, res, 512, client_id);
    if (res_len <= 0) {
        free(req);
        return -res_len; /* handshake_read return wsc_err_code as negative value */
    }

    free(req);

    return WSC_OK;
}

static int make_non_block(int fd)
{
    int flags, r;
    while (true) {
        flags = fcntl(fd, F_GETFL, 0);
        if (-1 == flags) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        break;
    }

    while (true) {
        r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        if (-1 == r) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        break;
    }

    return 0;
}

wsc_err_code wsc_connect(wsc_t *wsc, const char *host, uint16_t port, const char *path,
                         wsc_headers_t *headers, esp_tls_cfg_t *tls_cfg)
{
    wsc_err_code err;

    if (NULL != tls_cfg) {
        /* force nonblock */
        tls_cfg->non_block = true;

        wsc->tls = esp_tls_conn_new(host, strlen(host), port, tls_cfg);
        if (NULL == wsc->tls) {
            ESP_LOGE(TAG, "failed to create tls connection to server");
            return WSC_ERR_CONNECT;
        }
    } else {
        const struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
        };
        struct addrinfo *res;
        char addr_str[46];

        ESP_LOGD(TAG, "getaddrinfo: %s", host);
        int r = getaddrinfo(host, NULL, &hints, &res);
        if (0 != r) {
            ESP_LOGE(TAG, "getaddrinfo error: %d", errno);
            return WSC_ERR_HANDSHAKE_ADDRINFO;
        }
        if (NULL == res) {
            ESP_LOGE(TAG, "getaddrinfo failed: cannot found address");
            return WSC_ERR_HANDSHAKE_NO_ADDRESS;
        }

        if (res->ai_family == AF_INET) {
            ((struct sockaddr_in *)res->ai_addr)->sin_port = htons(port);
            struct in_addr *addr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
            inet_ntoa_r(*addr, addr_str, sizeof(addr_str) - 1);
            ESP_LOGD(TAG, "DNS lookup succeeded: IP=%s", addr_str);
        } else {
            ((struct sockaddr_in6 *)res->ai_addr)->sin6_port = htons(port);
            struct in6_addr *addr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
            ESP_LOGD(TAG, "DNS lookup succeeded: IP=%s", inet6_ntoa(*addr));
        }

        wsc->fd = socket(res->ai_family, res->ai_socktype, 0);
        if (-1 == wsc->fd) {
            ESP_LOGE(TAG, "failed to create socket: %d", errno);
            freeaddrinfo(res);
            return WSC_ERR_CREATE_SOCKET;
        }

        r = connect(wsc->fd, res->ai_addr, res->ai_addrlen);
        if (-1 == r) {
            ESP_LOGE(TAG, "connection failed: %d", errno);
            freeaddrinfo(res);
            return WSC_ERR_CONNECT;
        }

        freeaddrinfo(res);
    }

    err = wsc_handshake(wsc, host, port, path, headers);
    if (WSC_OK != err) {
        ESP_LOGE(TAG, "handshake failed: %d", err);
        return err;
    }
    ESP_LOGD(TAG, "connection succeeded");

    if (NULL == wsc->tls && -1 == make_non_block(wsc->fd)) {
        ESP_LOGE(TAG, "failed to make socket to unblocking mode");
        return WSC_ERR_SET_SOCKETOPT;
    }

    return WSC_OK;
}

wsc_err_code wsc_shutdown(wsc_t *wsc)
{
    int shutdown = 1;
    if (!xQueueSendToBack(wsc->shutdown_queue, &shutdown, 0)) {
        return WSC_ERR_SHUTDOWN_QUEUE_FULL;
    }
    return WSC_OK;
}

wsc_err_code wsc_send(wsc_t *wsc, wsc_msg_t *msg)
{
    if (!xQueueSendToBack(wsc->send_queue, msg, 0)) {
        ESP_LOGE(TAG, "send queue is full");
        return WSC_ERR_SEND_QUEUE_FULL;
    }
    return WSC_OK;
}

static void wsc_select_task(void *p)
{
    wsc_t *w = (wsc_t *)p;

    struct timeval tv = {
        .tv_sec = 0,
        .tv_usec = 10000,
    };
    fd_set rfds;

    while (wslay_event_want_read(w->ctx)) {
        int fd = w->tls ? w->tls->sockfd : w->fd;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        int s = select(fd + 1, &rfds, NULL, NULL, &tv);

        if (s < 0) {
            ESP_LOGE(TAG, "select failed");
            wsc_shutdown(w);
            break;
        } else if (0 == s) {
            /* timeout */
        } else {
            int available = 1;
            xQueueSendToBack(w->recv_queue, &available, 0);
        }
    }

    vTaskDelay(portMAX_DELAY); /* task will delete from main task*/
}

wsc_err_code wsc_run(wsc_t *wsc)
{
    TaskHandle_t hSelect;
    xTaskCreate(wsc_select_task, "wsc-internal", 1024, wsc, 5, &hSelect);

    while (wslay_event_want_read(wsc->ctx)) {
        int available = 0;
        if (xQueueReceive(wsc->recv_queue, &available, 0) && 1 == available) {
            int r = wslay_event_recv(wsc->ctx);
            if (0 != r) {
                ESP_LOGE(TAG, "recv error: %d", r);
                return WSC_ERR_RECV;
            }
        }

        int shutdown = 0;
        if (xQueueReceive(wsc->shutdown_queue, &shutdown, 0) && 1 == shutdown) {
            ESP_LOGD(TAG, "shutdown received. stop loop");
            break;
        }

        wsc_msg_t msg;
        if (xQueueReceive(wsc->send_queue, &msg, 0)) {
            wslay_event_queue_msg(wsc->ctx, &msg);
            wslay_event_send(wsc->ctx);
            if (NULL != msg.msg) {
                free((uint8_t *)msg.msg);
            }
        }
    }

    vTaskDelete(hSelect);

    return WSC_OK;
}
