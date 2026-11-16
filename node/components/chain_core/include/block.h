#ifndef BLOCK_H
#define BLOCK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "krst_tx.h"

#define BLOCK_MAX_TX    9

typedef struct __attribute__((packed)) {
    uint32_t height;                      // numer bloku
    uint8_t  prev_hash[KRST_HASH_SIZE];   // hash rodzica
    uint8_t  merkle_root[KRST_HASH_SIZE]; // skrót wszystkich tx
    uint32_t timestamp;                   // czas wykopania (unix)
    uint32_t target;                      // próg PoW
    uint32_t nonce;                       // zmieniany przy kopaniu
} block_header_t;

typedef struct __attribute__((packed)) {
    block_header_t header;       // hashowany w PoW
    uint16_t tx_count;           // ile tx
    krst_tx_t txs[BLOCK_MAX_TX]; // txs[0] = coinbase
} block_t;

_Static_assert(sizeof(block_header_t) == 80, "Rozmiar naglowka jest czescia protokolu");

typedef enum {
    BLOCK_OK = 0,
    BLOCK_ERR_TRUNCATED,
    BLOCK_ERR_TOO_MANY_TX,
    BLOCK_ERR_SIZE,
    BLOCK_ERR_NO_TX,
    BLOCK_ERR_MERKLE,
    BLOCK_ERR_POW,
    BLOCK_ERR_TARGET,
    BLOCK_ERR_HEIGHT,
    BLOCK_ERR_TIMESTAMP,
    BLOCK_ERR_COINBASE,
    BLOCK_ERR_TX_UNSUPPORTED
} block_result_t;

// nazwa błędu do logów
const char *block_result_str(block_result_t result);

// hash nagłówka = id bloku
void block_header_hash(const block_header_t *header, uint8_t out_hash[KRST_HASH_SIZE]);

// korzeń Merkle, false = 0 albo za dużo tx
bool block_merkle_root(const krst_tx_t *txs, uint16_t tx_count, uint8_t out_root[KRST_HASH_SIZE]);

// rozmiar w sieci/na flashu (tylko użyte tx)
size_t block_serialized_size(const block_t *block);

// bezpieczny odczyt z niezaufanego bufora
block_result_t block_parse(const uint8_t *data, size_t data_len, block_t *out_block);

// reguły bez znajomości łańcucha
block_result_t block_check_structure(const block_t *block);

#endif
