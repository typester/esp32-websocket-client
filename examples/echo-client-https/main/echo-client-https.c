#include <assert.h>
#include <string.h>

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

/* config */
#include "sdkconfig.h"
#define EXAMPLE_SSID CONFIG_SSID
#define EXAMPLE_PASS CONFIG_PASS
#define EXAMPLE_WS_SERVER CONFIG_WS_SERVER
#define EXAMPLE_WS_PORT CONFIG_WS_PORT

static const char *TAG = "echo-client-https";

extern const uint8_t server_pem_start[] asm("_binary_server_pem_start");
extern const uint8_t server_pem_end[] asm("_binary_server_pem_end");

static EventGroupHandle_t s_wifi_event_group;
static const int CONNECTED_BIT = BIT0;

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
            xEventGroupSetBits(s_wifi_event_group, CONNECTED_BIT);
        }
        break;
    }
    case SYSTEM_EVENT_STA_DISCONNECTED:
        xEventGroupClearBits(s_wifi_event_group, CONNECTED_BIT);
        esp_wifi_connect();
        break;
    default:
        break;
    }
    return ESP_OK;
    ;
}

static void wsc_send_task(void *p)
{
    wsc_t *w = (wsc_t *)p;
    char buf[64];
    size_t counter = 0;

    while (true) {
        counter++;
        snprintf(buf, 64, "hello %u", (uint32_t)counter);

        wsc_msg_t msg = {
            .opcode = 2,
            .msg = (const unsigned char *)strdup(buf),
            .msg_length = strlen(buf),
        };

        wsc_send(w, &msg);

        vTaskDelay(3000 / portTICK_PERIOD_MS);
    }
}

static void msg_callback(wsc_t *wsc, const struct wslay_event_on_msg_recv_arg *msg)
{
    ESP_LOGW(TAG, "got msg opcode=%d", msg->opcode);
    ESP_LOG_BUFFER_HEXDUMP(TAG, msg->msg, msg->msg_length, ESP_LOG_WARN);
}

static void wsc_task()
{
    ESP_LOGI(TAG, "wsc_task started");

    /* waiting network available */
    xEventGroupWaitBits(s_wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);

    wsc_err_code err;
    wsc_t wsc;

    err = wsc_init(&wsc);
    assert(err == WSC_OK);
    wsc.msg_callback = msg_callback;

    esp_tls_cfg_t tls_cfg = {
        .timeout_ms = 10 * 1000,
        .cacert_pem_buf = server_pem_start,
        .cacert_pem_bytes = server_pem_end - server_pem_start,
    };
    err = wsc_connect(&wsc, EXAMPLE_WS_SERVER, EXAMPLE_WS_PORT, "/", NULL, &tls_cfg);

    if (WSC_OK != err) {
        ESP_LOGE(TAG, "failed to connect: %d", err);
        wsc_close(&wsc);
        vTaskDelete(NULL);
    }
    ESP_LOGI(TAG, "tls connection success");

    /* start  */
    TaskHandle_t send_task;
    xTaskCreate(wsc_send_task, "wsc_send", (1024 * 2), &wsc, 5, &send_task);

    err = wsc_run(&wsc);
    if (ESP_OK != err) {
        ESP_LOGE(TAG, "receive error: %d", err);
        wsc_close(&wsc);
        vTaskDelete(NULL);
        return;
    }

    vTaskDelete(send_task);
    wsc_close(&wsc);

    ESP_LOGI(TAG, "wsc_task done");

    vTaskDelete(NULL);
}

void app_main()
{
    /* initialize nvs */
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_PAGE_FULL || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }
    ESP_ERROR_CHECK(err);

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
