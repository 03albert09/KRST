idf_component_register(
    SRCS
        "main.c"
        "wallet_vault.c"
        "wallet_comm.c"
        "wallet_cli.c"
        "wallet_bip39.c"
        "wallet_trng.c"
    INCLUDE_DIRS "."
    REQUIRES krst_common nvs_flash mbedtls efuse esp_hw_support esp_wifi esp_event esp_netif
)
