#include <string.h>
#include <assert.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "wsc.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"

#include "sdkconfig.h"

/* config */
#define EXAMPLE_SSID CONFIG_SSID
#define EXAMPLE_PASS CONFIG_PASS
#define EXAMPLE_WS_SERVER CONFIG_WS_SERVER
#define EXAMPLE_WS_PORT CONFIG_WS_PORT

static const char *TAG = "echo-client";

static EventGroupHandle_t s_wifi_event_group;
static const int CONNECTED_BIT = BIT0;
static const int CONNECTED6_BIT = BIT1;

static esp_err_t wifi_event_handler(void *ctx, system_event_t *event)
{
    switch (event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_CONNECTED:
        /* start ipv6 */
        tcpip_adapter_create_ip6_linklocal(TCPIP_ADAPTER_IF_STA);
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(s_wifi_event_group, CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_GOT_IP6: {
        char addr_str[46];
        ip6_addr_t addr;

        inet6_ntoa_r(event->event_info.got_ip6.ip6_info.ip, addr_str, sizeof(addr_str) - 1);
        ESP_LOGW(TAG, "got ipv6 addr: %s", addr_str);
        tcpip_adapter_get_ip6_linklocal(TCPIP_ADAPTER_IF_STA, &addr);

        if (0 == memcmp(&event->event_info.got_ip6.ip6_info.ip, &addr, sizeof(ip6_addr_t))) {
            ESP_LOGW(TAG, "but it is created by me");
        } else {
            xEventGroupSetBits(s_wifi_event_group, CONNECTED6_BIT);
        }
        break;
    }
    case SYSTEM_EVENT_STA_DISCONNECTED:
        xEventGroupClearBits(s_wifi_event_group, CONNECTED_BIT);
        xEventGroupClearBits(s_wifi_event_group, CONNECTED6_BIT);
        esp_wifi_connect();
        break;
    default:
        break;
    }

    return ESP_OK;
}

static void msg_callback(wsc_t *wsc, const struct wslay_event_on_msg_recv_arg *msg)
{
    ESP_LOGW(TAG, "got msg opcode=%d", msg->opcode);
    ESP_LOG_BUFFER_HEXDUMP(TAG, msg->msg, msg->msg_length, ESP_LOG_WARN);

    /* echo back to server */
    uint8_t *echo_msg = NULL;
    if (msg->msg_length > 0) {
        if (0 == strncmp((const char *)msg->msg, "close", msg->msg_length)) {
            ESP_LOGI(TAG, "shutdown message received. closing connection");
            wsc_shutdown(wsc);
            return;
        }

        echo_msg = malloc(msg->msg_length);
        assert(NULL != echo_msg);
        memcpy(echo_msg, msg->msg, msg->msg_length);
    }

    wsc_msg_t echo = {0x02, echo_msg, msg->msg_length};
    wsc_send(wsc, &echo);
}

static void wsc_task()
{
    xEventGroupWaitBits(s_wifi_event_group, CONNECTED_BIT | CONNECTED6_BIT, false, false,
                        portMAX_DELAY);

    wsc_err_code err;
    wsc_t wsc;

    err = wsc_init(&wsc);
    if (WSC_OK != err) {
        ESP_LOGE(TAG, "failed to init wsc");
        vTaskDelete(NULL);
        return;
    }
    wsc.msg_callback = msg_callback;

    wsc_headers_t *headers = wsc_headers_new(2);
    wsc_headers_add(headers, "User-Agent", "esp32-echo-client");
    wsc_headers_add(headers, "X-Foo", "bar!");

    err = wsc_connect(&wsc, EXAMPLE_WS_SERVER, EXAMPLE_WS_PORT, "/stream", headers);
    wsc_headers_free(headers);
    if (WSC_OK != err) {
        ESP_LOGE(TAG, "failed to connect: %d", err);
        wsc_close(&wsc);
        vTaskDelete(NULL);
        return;
    }

    err = wsc_run(&wsc);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "receive error: %d", err);
        wsc_close(&wsc);
        vTaskDelete(NULL);
        return;
    }

    wsc_close(&wsc);

    ESP_LOGI(TAG, "wsc_task done");

    vTaskDelete(NULL);
}

void app_main()
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_PAGE_FULL || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    s_wifi_event_group = xEventGroupCreate();
    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(wifi_event_handler, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    wifi_config_t wifi_config = {
        .sta =
            {
                .ssid = EXAMPLE_SSID,
                .password = EXAMPLE_PASS,
            },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    xTaskCreate(wsc_task, "wsc_task", (1024 * 8), NULL, 5, NULL);
}
