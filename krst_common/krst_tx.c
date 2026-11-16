#include "krst_tx.h"
#include <stddef.h>
#include "mbedtls/sha256.h"

// Obliczenie skrótu pól transakcji objętych podpisem
void krst_tx_signing_hash(const krst_tx_t *tx, uint8_t out_hash[KRST_HASH_SIZE]) {
    mbedtls_sha256((const unsigned char *)tx, offsetof(krst_tx_t, signature), out_hash, 0);
}

// Sprawdzenie prefiksu klucza skompresowanego
bool krst_address_has_valid_prefix(const uint8_t address[KRST_PUBKEY_SIZE]) {
    return address[0] == 0x02 || address[0] == 0x03;
}
