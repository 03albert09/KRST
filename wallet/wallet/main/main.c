#include "nvs_flash.h"
#include "esp_err.h"
#include "wallet_comm.h"
#include "wallet_cli.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// Glowna funkcja startowa mikrokontrolera
void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wallet_comm_init();
    wallet_cli_start();

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
