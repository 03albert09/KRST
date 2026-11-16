#include "block.h"
#include <string.h>
#include "mbedtls/sha256.h"

#define MERKLE_LEAF_PREFIX 0x00
#define MERKLE_NODE_PREFIX 0x01

#define BLOCK_BASE_SIZE (offsetof(block_t, txs))

// Nazwa błędu do logów
const char *block_result_str(block_result_t result) {
    switch (result) {
        case BLOCK_OK:                 return "BLOCK_OK";
        case BLOCK_ERR_TRUNCATED:      return "BLOCK_ERR_TRUNCATED";
        case BLOCK_ERR_TOO_MANY_TX:    return "BLOCK_ERR_TOO_MANY_TX";
        case BLOCK_ERR_SIZE:           return "BLOCK_ERR_SIZE";
        case BLOCK_ERR_NO_TX:          return "BLOCK_ERR_NO_TX";
        case BLOCK_ERR_MERKLE:         return "BLOCK_ERR_MERKLE";
        case BLOCK_ERR_POW:            return "BLOCK_ERR_POW";
        case BLOCK_ERR_TARGET:         return "BLOCK_ERR_TARGET";
        case BLOCK_ERR_HEIGHT:         return "BLOCK_ERR_HEIGHT";
        case BLOCK_ERR_TIMESTAMP:      return "BLOCK_ERR_TIMESTAMP";
        case BLOCK_ERR_COINBASE:       return "BLOCK_ERR_COINBASE";
        case BLOCK_ERR_TX_UNSUPPORTED: return "BLOCK_ERR_TX_UNSUPPORTED";
    }
    return "BLOCK_ERR_UNKNOWN";
}

// Obliczenie skrótu bloku
void block_header_hash(const block_header_t *header, uint8_t out_hash[KRST_HASH_SIZE]) {
    mbedtls_sha256((const unsigned char *)header, sizeof(block_header_t), out_hash, 0);
}

// Skrót liścia drzewa Merkle
static void merkle_hash_leaf(const krst_tx_t *tx, uint8_t out_hash[KRST_HASH_SIZE]) {
    const uint8_t prefix = MERKLE_LEAF_PREFIX;
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, &prefix, 1);
    mbedtls_sha256_update(&ctx, (const uint8_t *)tx, sizeof(krst_tx_t));
    mbedtls_sha256_finish(&ctx, out_hash);
    mbedtls_sha256_free(&ctx);
}

// Skrót węzła wewnętrznego drzewa Merkle
static void merkle_hash_node(const uint8_t left[KRST_HASH_SIZE], const uint8_t right[KRST_HASH_SIZE],
                             uint8_t out_hash[KRST_HASH_SIZE]) {
    const uint8_t prefix = MERKLE_NODE_PREFIX;
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, &prefix, 1);
    mbedtls_sha256_update(&ctx, left, KRST_HASH_SIZE);
    mbedtls_sha256_update(&ctx, right, KRST_HASH_SIZE);
    mbedtls_sha256_finish(&ctx, out_hash);
    mbedtls_sha256_free(&ctx);
}

// Obliczenie korzenia Merkle listy transakcji
bool block_merkle_root(const krst_tx_t *txs, uint16_t tx_count, uint8_t out_root[KRST_HASH_SIZE]) {
    if (tx_count == 0 || tx_count > BLOCK_MAX_TX) {
        return false;
    }

    uint8_t level[BLOCK_MAX_TX][KRST_HASH_SIZE];
    for (uint16_t i = 0; i < tx_count; i++) {
        merkle_hash_leaf(&txs[i], level[i]);
    }

    uint16_t count = tx_count;
    while (count > 1) {
        uint16_t next = 0;
        for (uint16_t i = 0; i < count; i += 2) {
            if (i + 1 < count) {
                merkle_hash_node(level[i], level[i + 1], level[next]);
            } else if (next != i) {
                memcpy(level[next], level[i], KRST_HASH_SIZE);
            }
            next++;
        }
        count = next;
    }

    memcpy(out_root, level[0], KRST_HASH_SIZE);
    return true;
}

// Rozmiar bloku w formacie sieciowym
size_t block_serialized_size(const block_t *block) {
    return BLOCK_BASE_SIZE + (size_t)block->tx_count * sizeof(krst_tx_t);
}

// Bezpieczny odczyt bloku z niezaufanego bufora
block_result_t block_parse(const uint8_t *data, size_t data_len, block_t *out_block) {
    if (data == NULL || data_len < BLOCK_BASE_SIZE) {
        return BLOCK_ERR_TRUNCATED;
    }

    uint16_t tx_count;
    memcpy(&tx_count, data + offsetof(block_t, tx_count), sizeof(tx_count));
    if (tx_count > BLOCK_MAX_TX) {
        return BLOCK_ERR_TOO_MANY_TX;
    }
    if (data_len != BLOCK_BASE_SIZE + (size_t)tx_count * sizeof(krst_tx_t)) {
        return BLOCK_ERR_SIZE;
    }

    memcpy(out_block, data, data_len);
    return BLOCK_OK;
}

// Sprawdzenie reguł niezależnych od stanu łańcucha
block_result_t block_check_structure(const block_t *block) {
    if (block->tx_count == 0) {
        return BLOCK_ERR_NO_TX;
    }
    if (block->tx_count > BLOCK_MAX_TX) {
        return BLOCK_ERR_TOO_MANY_TX;
    }

    uint8_t root[KRST_HASH_SIZE];
    if (!block_merkle_root(block->txs, block->tx_count, root) ||
        memcmp(root, block->header.merkle_root, KRST_HASH_SIZE) != 0) {
        return BLOCK_ERR_MERKLE;
    }
    return BLOCK_OK;
}
