#include "wallet_comm.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

// Wypisanie bufora binarnego w formacie HEX
static void print_hex_line(const char *label, const uint8_t *buf, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\r\n");
}

// Inicjalizacja modulu bezposredniej komunikacji IP
void wallet_comm_init(void) {
  
}

// Bezposrednia wysylka transakcji pod adres IP
esp_err_t wallet_comm_send_tx(const wallet_transaction_t *tx, const char *target_ip) {
    if (!tx || !target_ip || strlen(target_ip) == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    printf("\r\n=================== [WYSYLKA PAKIETU IP] ===================\r\n");
    printf("  Docelowy adres IP : %s\r\n", target_ip);
    printf("  Rozmiar pakietu   : %u B\r\n", (unsigned int)sizeof(wallet_transaction_t));
    printf("  Nonce (licznik)   : %" PRIu32 "\r\n", tx->nonce);
    printf("  Kwota transakcji  : %" PRIu64 "\r\n", tx->amount);
    print_hex_line("  Nadawca (Pubkey)  : ", tx->sender_pubkey, WALLET_PUBKEY_SIZE);
    print_hex_line("  Odbiorca (Pubkey) : ", tx->recipient_pubkey, WALLET_PUBKEY_SIZE);
    print_hex_line("  Hash SHA-256      : ", tx->tx_hash, WALLET_HASH_SIZE);
    print_hex_line("  Podpis ECDSA      : ", tx->signature, WALLET_SIG_SIZE);
    printf("============================================================\r\n");

    return ESP_OK;
}