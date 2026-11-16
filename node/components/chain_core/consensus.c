#include "consensus.h"
#include <string.h>
#include "sdkconfig.h"

// Sprawdzenie, czy cały bufor składa się z zer
static bool is_all_zero(const uint8_t *data, size_t len) {
    uint8_t accumulated = 0;
    for (size_t i = 0; i < len; i++) {
        accumulated |= data[i];
    }
    return accumulated == 0;
}

// Sprawdzenie trudności hasha
bool consensus_check_pow(const uint8_t hash[KRST_HASH_SIZE], uint32_t target) {
    uint32_t prefix = ((uint32_t)hash[0] << 24) | ((uint32_t)hash[1] << 16) |
                      ((uint32_t)hash[2] << 8) | (uint32_t)hash[3];
    return prefix < target;
}

// Obliczenie pracy włożonej w blok
uint64_t consensus_block_work(uint32_t target) {
    if (target == 0) {
        return 0;
    }
    return (1ULL << 32) / target;
}

// Wyznaczenie progu dla kolejnego bloku (na razie stała trudność)
uint32_t consensus_next_target(const consensus_parent_t *parent) {
    (void)parent;
    return (uint32_t)CONFIG_KRST_POW_TARGET;
}

// Sprawdzenie reguł nagłówka zależnych od rodzica
block_result_t consensus_check_header_context(const block_header_t *header, const consensus_parent_t *parent,
                                              uint32_t now, bool clock_synced) {
    if (header->target != consensus_next_target(parent)) {
        return BLOCK_ERR_TARGET;
    }
    if (header->height != parent->height + 1) {
        return BLOCK_ERR_HEIGHT;
    }
    if (header->timestamp <= parent->timestamp) {
        return BLOCK_ERR_TIMESTAMP;
    }
    if (clock_synced && (uint64_t)header->timestamp > (uint64_t)now + CONSENSUS_MAX_FUTURE_SEC) {
        return BLOCK_ERR_TIMESTAMP;
    }
    return BLOCK_OK;
}

// Sprawdzenie poprawności transakcji coinbase
static bool is_valid_coinbase(const krst_tx_t *tx, uint32_t height) {
    return tx->type == KRST_TX_COINBASE &&
           tx->nonce == height &&
           tx->amount == CONSENSUS_BLOCK_REWARD &&
           is_all_zero(tx->sender, sizeof(tx->sender)) &&
           is_all_zero(tx->signature, sizeof(tx->signature)) &&
           krst_address_has_valid_prefix(tx->recipient);
}

// Sprawdzenie reguł transakcji w bloku
block_result_t consensus_check_transactions(const block_t *block) {
    if (block->tx_count == 0) {
        return BLOCK_ERR_NO_TX;
    }
    if (!is_valid_coinbase(&block->txs[0], block->header.height)) {
        return BLOCK_ERR_COINBASE;
    }

    for (uint16_t i = 1; i < block->tx_count; i++) {
        if (block->txs[i].type == KRST_TX_COINBASE) {
            return BLOCK_ERR_COINBASE;
        }
    }

    if (block->tx_count > 1) {
        return BLOCK_ERR_TX_UNSUPPORTED;
    }
    return BLOCK_OK;
}

// Wypełnienie stałego nagłówka bloku genesis
void consensus_genesis_header(block_header_t *out_header) {
    memset(out_header, 0, sizeof(*out_header));
    out_header->timestamp = CONSENSUS_GENESIS_TIMESTAMP;
    out_header->target = CONSENSUS_GENESIS_TARGET;
}
