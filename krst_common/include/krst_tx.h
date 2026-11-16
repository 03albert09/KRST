#ifndef KRST_TX_H
#define KRST_TX_H

#include <stdbool.h>
#include <stdint.h>

#define KRST_PUBKEY_SIZE     33
#define KRST_SIGNATURE_SIZE  64
#define KRST_HASH_SIZE       32

typedef enum {
    KRST_TX_COINBASE = 0,
    KRST_TX_TRANSFER = 1
} krst_tx_type_t;

typedef struct __attribute__((packed)) {
    uint8_t  type;                           // coinbase / przelew
    uint32_t nonce;                          // coinbase: = wysokość bloku
    uint8_t  sender[KRST_PUBKEY_SIZE];       // klucz nadawcy (coinbase: zera)
    uint8_t  recipient[KRST_PUBKEY_SIZE];    // adres odbiorcy
    uint64_t amount;                         // kwota
    uint8_t  signature[KRST_SIGNATURE_SIZE]; // podpis nadawcy (coinbase: zera)
} krst_tx_t;

_Static_assert(sizeof(krst_tx_t) == 143, "Rozmiar krst_tx_t jest czescia protokolu");

// hash pól objętych podpisem
void krst_tx_signing_hash(const krst_tx_t *tx, uint8_t out_hash[KRST_HASH_SIZE]);

// czy adres to skompresowany klucz (02/03)
bool krst_address_has_valid_prefix(const uint8_t address[KRST_PUBKEY_SIZE]);

#endif
