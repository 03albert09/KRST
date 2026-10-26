#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "esp_err.h"

// Nasze moduły
#include "node_wifi.h"
#include "node_p2p.h"
#include "node_cli.h"

void app_main(void) {
    // 1. Wyłączenie buforowania sprzętowego z wejścia/wyjścia (naprawa timeoutów USB)
    //setvbuf(stdin, NULL, _IONBF, 0);
    //setvbuf(stdout, NULL, _IONBF, 0);

    // 2. Inicjalizacja NVS (niezbędna dla WiFi oraz kluczy P2P)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // 3. Uruchomienie poszczególnych podsystemów
    node_wifi_init();          // Warstwa sprzętowa WiFi
    node_p2p_init();           // Kryptografia i struktury RAM
    node_p2p_start_tasks();    // Wątki sieciowe TCP (czekają na WiFi)
    node_cli_start();          // Wątek interfejsu UART/USB

    // 4. RTOS Yield (Main Task odpoczywa, a tło pracuje)
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}