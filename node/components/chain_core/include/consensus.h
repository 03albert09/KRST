#ifndef CONSENSUS_H
#define CONSENSUS_H

#include <stdbool.h>
#include <stdint.h>
#include "block.h"

#define CONSENSUS_BLOCK_REWARD      50
#define CONSENSUS_MAX_FUTURE_SEC    120
#define CONSENSUS_GENESIS_TIMESTAMP 1793491200u
#define CONSENSUS_GENESIS_TARGET    0xFFFFFFFFu

typedef struct {
    uint32_t height;    // dziecko musi mieć +1
    uint32_t timestamp; // dziecko musi mieć później
    uint32_t target;    // z niego próg dziecka
} consensus_parent_t;

// hash < target
bool consensus_check_pow(const uint8_t hash[KRST_HASH_SIZE], uint32_t target);

// praca bloku = 2^32 / target
uint64_t consensus_block_work(uint32_t target);

// próg dziecka (na razie stały)
uint32_t consensus_next_target(const consensus_parent_t *parent);

// wysokość, czas, próg względem rodzica
block_result_t consensus_check_header_context(const block_header_t *header, const consensus_parent_t *parent,
                                              uint32_t now, bool clock_synced);

// coinbase i reszta tx
block_result_t consensus_check_transactions(const block_t *block);

// stały nagłówek genesis
void consensus_genesis_header(block_header_t *out_header);

#endif
