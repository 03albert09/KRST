#include "chain_test_helpers.h"
#include <string.h>
#include "unity.h"
#include "chain.h"
#include "consensus.h"

// Buduje poprawne dziecko podanego rodzica z coinbase na adres zalezny od wariantu
void th_make_child(block_t *block, const uint8_t parent_hash[KRST_HASH_SIZE],
                   uint32_t parent_height, uint32_t parent_timestamp, uint8_t variant) {
    memset(block, 0, sizeof(*block));

    block_header_t *header = &block->header;
    header->height = parent_height + 1;
    memcpy(header->prev_hash, parent_hash, KRST_HASH_SIZE);
    header->timestamp = parent_timestamp + 1 + variant;
    consensus_parent_t parent = { .height = parent_height, .timestamp = parent_timestamp };
    header->target = consensus_next_target(&parent);

    block->tx_count = 1;
    krst_tx_t *coinbase = &block->txs[0];
    coinbase->type = KRST_TX_COINBASE;
    coinbase->nonce = header->height;
    coinbase->amount = CONSENSUS_BLOCK_REWARD;
    coinbase->recipient[0] = 0x02;
    memset(coinbase->recipient + 1, variant + 1, 32);

    th_finish(block);
}

// Liczy korzen Merkle i szuka nonce spelniajacego PoW
void th_finish(block_t *block) {
    if (block->tx_count > 0) {
        TEST_ASSERT_TRUE(block_merkle_root(block->txs, block->tx_count, block->header.merkle_root));
    }

    uint8_t hash[KRST_HASH_SIZE];
    for (uint32_t nonce = 0; nonce < 1000000; nonce++) {
        block->header.nonce = nonce;
        block_header_hash(&block->header, hash);
        if (consensus_check_pow(hash, block->header.target)) {
            return;
        }
    }
    TEST_FAIL_MESSAGE("Nie znaleziono nonce");
}

// Szuka nonce, ktory nie spelnia PoW
void th_break_pow(block_t *block) {
    uint8_t hash[KRST_HASH_SIZE];
    for (uint32_t nonce = 0; nonce < 1000000; nonce++) {
        block->header.nonce = nonce;
        block_header_hash(&block->header, hash);
        if (!consensus_check_pow(hash, block->header.target)) {
            return;
        }
    }
    TEST_FAIL_MESSAGE("Nie znaleziono nonce");
}

// Przywraca lancuch do samego bloku genesis
void th_fresh_chain(void) {
    TEST_ASSERT_EQUAL(ESP_OK, chain_init());
    TEST_ASSERT_EQUAL(ESP_OK, chain_reset());
}

// Liczy hash bloku genesis
void th_genesis_hash(uint8_t out_hash[KRST_HASH_SIZE]) {
    block_header_t genesis;
    consensus_genesis_header(&genesis);
    block_header_hash(&genesis, out_hash);
}
