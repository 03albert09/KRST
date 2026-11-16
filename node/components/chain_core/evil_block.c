#include "evil_block.h"
#include <string.h>
#include "consensus.h"
#include "miner.h"

#define EVIL_UNKNOWN_PARENT_BYTE 0xEE

// Zwiększenie progu, czyli obniżenie trudności
static uint32_t easier_target(uint32_t target) {
    return target >= 0x80000000u ? 0xFFFFFFFFu : target * 2;
}

// Wybór nonce, który nie spełnia PoW
static void break_pow(block_header_t *header) {
    uint8_t hash[KRST_HASH_SIZE];
    block_header_hash(header, hash);

    while (consensus_check_pow(hash, header->target)) {
        header->nonce++;
        block_header_hash(header, hash);
    }
}

// Ponowne policzenie korzenia po zmianie transakcji, żeby wada była tylko jedna
static void refresh_merkle_root(block_t *block) {
    block_merkle_root(block->txs, block->tx_count, block->header.merkle_root);
}

// Zbudowanie kandydata z daną wadą
void evil_block_prepare(block_t *out_block, evil_block_kind_t kind, const chain_tip_t *tip,
                        const uint8_t payout[KRST_PUBKEY_SIZE], uint32_t now) {
    miner_build_block(out_block, tip, payout, now);
    block_header_t *header = &out_block->header;

    switch (kind) {
        case EVIL_BLOCK_POW:
            break_pow(header);
            break;
        case EVIL_BLOCK_MERKLE:
            header->merkle_root[0] ^= 0xFF;
            break;
        case EVIL_BLOCK_TARGET:
            header->target = easier_target(header->target);
            break;
        case EVIL_BLOCK_HEIGHT:
            header->height++;
            out_block->txs[0].nonce = header->height;
            refresh_merkle_root(out_block);
            break;
        case EVIL_BLOCK_TIMESTAMP:
            header->timestamp = tip->timestamp;
            break;
        case EVIL_BLOCK_COINBASE:
            out_block->txs[0].amount++;
            refresh_merkle_root(out_block);
            break;
        case EVIL_BLOCK_ORPHAN:
            memset(header->prev_hash, EVIL_UNKNOWN_PARENT_BYTE, KRST_HASH_SIZE);
            break;
        case EVIL_BLOCK_FORMAT:
            break;
    }
}

// Sprawdzenie, czy wada jest widoczna dopiero po kontroli PoW
bool evil_block_needs_mining(evil_block_kind_t kind) {
    return kind != EVIL_BLOCK_POW && kind != EVIL_BLOCK_FORMAT;
}

// Wyznaczenie liczby bajtów do wysłania
uint32_t evil_block_wire_length(const block_t *block, evil_block_kind_t kind) {
    uint32_t length = (uint32_t)block_serialized_size(block);
    return kind == EVIL_BLOCK_FORMAT ? length - 1 : length;
}
