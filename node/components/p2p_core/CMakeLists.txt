idf_component_register(SRCS "node_p2p.c" "peer_table.c" "node_crypto.c" "p2p_protocol.c"
                    INCLUDE_DIRS "include"
                    REQUIRES mbedtls lwip
                    PRIV_REQUIRES nvs_flash)

target_compile_definitions(${COMPONENT_LIB} PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS)
