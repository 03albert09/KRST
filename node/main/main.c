#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "esp_err.h"

#include "node_wifi.h"
#include "node_p2p.h"
#include "node_cli.h"
#include "chain.h"
#include "chain_task.h"
#include "chain_net.h"

// Inicjalizacja NVS i uruchomienie łańcucha, WiFi, P2P oraz CLI
void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(chain_init());

    chain_net_transport_t chain_transport = {
        .send = node_p2p_send_to_peer,
        .broadcast = node_p2p_broadcast,
        .disconnect = node_p2p_disconnect,
    };
    chain_net_init(&chain_transport);

    chain_task_config_t chain_config = {
        .clock_synced = node_time_is_synced,
        .on_result = chain_net_on_block_result,
        .on_tick = chain_net_tick,
    };
    ESP_ERROR_CHECK(chain_task_start(&chain_config));

    node_wifi_init();
    node_p2p_init();

    node_p2p_handlers_t p2p_handlers = {
        .on_peer_authenticated = chain_net_on_peer_authenticated,
        .on_message = chain_net_handle_message,
    };
    node_p2p_set_handlers(&p2p_handlers);

    node_p2p_start_tasks();
    node_cli_start();

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}