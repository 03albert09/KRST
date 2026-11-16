#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "unity.h"
#include "unity_test_runner.h"
#include "esp_err.h"
#include "esp_netif.h"
#include "esp_partition.h"
#include "nvs_flash.h"

TEST_CASE("tabela partycji zawiera dziennik blokow", "[partitions]") {
    const esp_partition_t *chain = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x40, "chain");
    TEST_ASSERT_NOT_NULL(chain);
    TEST_ASSERT_EQUAL_HEX32(0x140000, chain->address);
    TEST_ASSERT_EQUAL_HEX32(0xC0000, chain->size);
}

// Odczyt linii ze stdin, bo to wejscie dziala na konsoli USB-Serial-JTAG
static void read_line(char *buf, size_t max_len) {
    size_t idx = 0;
    while (1) {
        int c = fgetc(stdin);
        if (c == EOF) {
            vTaskDelay(pdMS_TO_TICKS(15));
            continue;
        }
        if (c == '\r' || c == '\n') {
            buf[idx] = '\0';
            return;
        }
        if (idx < max_len - 1 && isprint(c)) {
            buf[idx++] = (char)c;
        }
    }
}

// Inicjalizacja NVS i stosu TCP/IP, potem uruchamianie wszystkich testow albo grupy z tagiem
void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());

    char line[64];
    while (1) {
        printf("\r\nEnter = wszystkie testy, [tag] = jedna grupa, np. [p2p_channel]\r\n");
        fflush(stdout);
        read_line(line, sizeof(line));

        UNITY_BEGIN();
        if (line[0] == '[') {
            unity_run_tests_by_tag(line, false);
        } else {
            unity_run_all_tests();
        }
        UNITY_END();
    }
}
