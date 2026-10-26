idf_component_register(SRCS "node_p2p.c" "peer_table.c" "node_crypto.c" "p2p_protocol.c" "node_cli.c" "node_wifi.c" "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash esp_wifi esp_netif esp_http_server mbedtls lwip)

target_compile_definitions(${COMPONENT_LIB} PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS)
target_compile_definitions(${COMPONENT_LIB} PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS)

