idf_component_register(SRCS "node_cli.c" "node_evil.c" "node_wifi.c" "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES chain_core p2p_core nvs_flash esp_wifi esp_netif mbedtls lwip)
