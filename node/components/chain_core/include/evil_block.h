#ifndef EVIL_BLOCK_H
#define EVIL_BLOCK_H

#include <stdbool.h>
#include <stdint.h>
#include "block.h"
#include "chain.h"

typedef enum {
    EVIL_BLOCK_POW,
    EVIL_BLOCK_MERKLE,
    EVIL_BLOCK_TARGET,
    EVIL_BLOCK_HEIGHT,
    EVIL_BLOCK_TIMESTAMP,
    EVIL_BLOCK_COINBASE,
    EVIL_BLOCK_ORPHAN,
    EVIL_BLOCK_FORMAT,
} evil_block_kind_t;

// blok z celowym błędem
void evil_block_prepare(block_t *out_block, evil_block_kind_t kind, const chain_tip_t *tip,
                        const uint8_t payout[KRST_PUBKEY_SIZE], uint32_t now);

// czy trzeba wykopać, żeby błąd był widoczny
bool evil_block_needs_mining(evil_block_kind_t kind);

// ile bajtów wysłać (FORMAT = o 1 za mało)
uint32_t evil_block_wire_length(const block_t *block, evil_block_kind_t kind);

#endif
