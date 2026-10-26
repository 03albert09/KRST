#include "wallet_trng.h"
#include "esp_random.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static bool s_wifi_subsystem_ready = false;
static int s_rf_enable_depth = 0;

// Inicjalizacja podsystemu sieciowego i Wi-Fi
static void ensure_wifi_subsystem_ready(void) {
    if (s_wifi_subsystem_ready) return;

    esp_netif_init();
    esp_event_loop_create_default();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t err = esp_wifi_init(&cfg);
    if (err == ESP_OK || err == ESP_ERR_INVALID_STATE) {
        esp_wifi_set_mode(WIFI_MODE_STA);
        s_wifi_subsystem_ready = true;
    }
}

// Wlaczenie toru radiowego i stabilizacja szumu
void wallet_trng_enable(void) {
    ensure_wifi_subsystem_ready();
    if (s_rf_enable_depth == 0) {
        esp_err_t err = esp_wifi_start();
        if (err == ESP_OK || err == ESP_ERR_WIFI_STATE) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }
    s_rf_enable_depth++;
}

// Wylaczenie toru radiowego i usypienie anteny
void wallet_trng_disable(void) {
    if (s_rf_enable_depth > 0) {
        s_rf_enable_depth--;
        if (s_rf_enable_depth == 0) {
            esp_wifi_stop();
        }
    }
}

// Pobranie losowych bajtow z anteny Wi-Fi
void wallet_trng_fill(void *buf, size_t len) {
    if (!buf || len == 0) return;

    bool local_enable = (s_rf_enable_depth == 0);
    if (local_enable) {
        wallet_trng_enable();
    }

    esp_fill_random(buf, len);

    if (local_enable) {
        wallet_trng_disable();
    }
}

// Callback losowosci antenowej dla mbed TLS
int wallet_trng_mbedtls_cb(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    wallet_trng_fill(buf, len);
    return 0;
}
