#include <string.h>
#include "unity.h"
#include "sdkconfig.h"
#include "consensus.h"
#include "block_vectors.h"

#define PARENT_TIMESTAMP 1793500000u

static block_t s_block;

// Rodzic na wysokosci 10 ze stalym znacznikiem czasu
static consensus_parent_t make_parent(void) {
    consensus_parent_t parent = {
        .height = 10,
        .timestamp = PARENT_TIMESTAMP,
        .target = CONFIG_KRST_POW_TARGET,
    };
    return parent;
}

// Poprawny naglowek dziecka podanego rodzica
static block_header_t make_child_header(const consensus_parent_t *parent) {
    block_header_t header;
    memset(&header, 0, sizeof(header));
    header.height = parent->height + 1;
    header.timestamp = parent->timestamp + 30;
    header.target = consensus_next_target(parent);
    return header;
}

// Poprawna transakcja coinbase dla podanej wysokosci
static void make_coinbase(krst_tx_t *tx, uint32_t height) {
    memset(tx, 0, sizeof(*tx));
    tx->type = KRST_TX_COINBASE;
    tx->nonce = height;
    tx->amount = CONSENSUS_BLOCK_REWARD;
    tx->recipient[0] = 0x02;
    memset(tx->recipient + 1, 0xAB, 32);
}

// Blok z sama transakcja coinbase
static void make_coinbase_block(block_t *block, uint32_t height) {
    memset(block, 0, sizeof(*block));
    block->header.height = height;
    block->tx_count = 1;
    make_coinbase(&block->txs[0], height);
}

// Hash o zadanych pierwszych 4 bajtach (big-endian)
static void make_hash(uint8_t hash[KRST_HASH_SIZE], uint32_t prefix, uint8_t rest) {
    memset(hash, rest, KRST_HASH_SIZE);
    hash[0] = (uint8_t)(prefix >> 24);
    hash[1] = (uint8_t)(prefix >> 16);
    hash[2] = (uint8_t)(prefix >> 8);
    hash[3] = (uint8_t)prefix;
}

TEST_CASE("PoW wymaga hasha scisle mniejszego od progu", "[consensus]") {
    uint8_t hash[KRST_HASH_SIZE];
    const uint32_t target = 0x00040000;

    make_hash(hash, target - 1, 0xFF);
    TEST_ASSERT_TRUE(consensus_check_pow(hash, target));

    make_hash(hash, target, 0x00);
    TEST_ASSERT_FALSE(consensus_check_pow(hash, target));

    make_hash(hash, target + 1, 0x00);
    TEST_ASSERT_FALSE(consensus_check_pow(hash, target));
}

TEST_CASE("PoW czyta poczatek hasha jako big-endian", "[consensus]") {
    uint8_t hash[KRST_HASH_SIZE];

    make_hash(hash, 0x01000000, 0x00);
    TEST_ASSERT_FALSE(consensus_check_pow(hash, 0x00040000));
}

TEST_CASE("PoW dla skrajnych progow", "[consensus]") {
    uint8_t hash[KRST_HASH_SIZE];

    make_hash(hash, 0x00000000, 0x00);
    TEST_ASSERT_FALSE(consensus_check_pow(hash, 0));
    TEST_ASSERT_TRUE(consensus_check_pow(hash, 1));

    make_hash(hash, 0xFFFFFFFF, 0xFF);
    TEST_ASSERT_FALSE(consensus_check_pow(hash, 0xFFFFFFFF));
}

TEST_CASE("praca bloku rosnie wraz z trudnoscia", "[consensus]") {
    TEST_ASSERT_EQUAL_UINT64(0, consensus_block_work(0));
    TEST_ASSERT_EQUAL_UINT64(1, consensus_block_work(0xFFFFFFFF));
    TEST_ASSERT_EQUAL_UINT64(1ULL << 14, consensus_block_work(1u << 18));
    TEST_ASSERT_EQUAL_UINT64(1ULL << 32, consensus_block_work(1));
}

TEST_CASE("trudnosc jest stala", "[consensus]") {
    consensus_parent_t parent = make_parent();
    TEST_ASSERT_EQUAL_HEX32(CONFIG_KRST_POW_TARGET, consensus_next_target(&parent));
}

TEST_CASE("genesis ma ustalony hash", "[consensus]") {
    block_header_t genesis;
    uint8_t hash[KRST_HASH_SIZE];
    consensus_genesis_header(&genesis);
    block_header_hash(&genesis, hash);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(BV_GENESIS_HASH, hash, sizeof(hash));
}

TEST_CASE("poprawny naglowek przechodzi kontrole wzgledem rodzica", "[consensus]") {
    consensus_parent_t parent = make_parent();
    block_header_t header = make_child_header(&parent);
    TEST_ASSERT_EQUAL(BLOCK_OK, consensus_check_header_context(&header, &parent, header.timestamp, true));
}

TEST_CASE("zly prog i wysokosc sa odrzucane", "[consensus]") {
    consensus_parent_t parent = make_parent();
    block_header_t header = make_child_header(&parent);
    const uint32_t now = header.timestamp;

    header.target = CONSENSUS_GENESIS_TARGET;
    TEST_ASSERT_EQUAL(BLOCK_ERR_TARGET, consensus_check_header_context(&header, &parent, now, true));

    header = make_child_header(&parent);
    header.height = parent.height;
    TEST_ASSERT_EQUAL(BLOCK_ERR_HEIGHT, consensus_check_header_context(&header, &parent, now, true));

    header.height = parent.height + 2;
    TEST_ASSERT_EQUAL(BLOCK_ERR_HEIGHT, consensus_check_header_context(&header, &parent, now, true));
}

TEST_CASE("czas bloku musi byc pozniejszy od rodzica", "[consensus]") {
    consensus_parent_t parent = make_parent();
    block_header_t header = make_child_header(&parent);

    header.timestamp = parent.timestamp;
    TEST_ASSERT_EQUAL(BLOCK_ERR_TIMESTAMP, consensus_check_header_context(&header, &parent, PARENT_TIMESTAMP, true));

    header.timestamp = parent.timestamp - 1;
    TEST_ASSERT_EQUAL(BLOCK_ERR_TIMESTAMP, consensus_check_header_context(&header, &parent, PARENT_TIMESTAMP, false));

    header.timestamp = parent.timestamp + 1;
    TEST_ASSERT_EQUAL(BLOCK_OK, consensus_check_header_context(&header, &parent, PARENT_TIMESTAMP, true));
}

TEST_CASE("czas z przyszlosci jest odrzucany tylko przy zsynchronizowanym zegarze", "[consensus]") {
    consensus_parent_t parent = make_parent();
    block_header_t header = make_child_header(&parent);
    const uint32_t now = parent.timestamp;

    header.timestamp = now + CONSENSUS_MAX_FUTURE_SEC;
    TEST_ASSERT_EQUAL(BLOCK_OK, consensus_check_header_context(&header, &parent, now, true));

    header.timestamp = now + CONSENSUS_MAX_FUTURE_SEC + 1;
    TEST_ASSERT_EQUAL(BLOCK_ERR_TIMESTAMP, consensus_check_header_context(&header, &parent, now, true));
    TEST_ASSERT_EQUAL(BLOCK_OK, consensus_check_header_context(&header, &parent, now, false));
}

TEST_CASE("kontrola czasu nie przepelnia sie przy duzych wartosciach", "[consensus]") {
    consensus_parent_t parent = make_parent();
    block_header_t header = make_child_header(&parent);

    header.timestamp = 0xFFFFFFFF;
    TEST_ASSERT_EQUAL(BLOCK_ERR_TIMESTAMP, consensus_check_header_context(&header, &parent, PARENT_TIMESTAMP, true));
    TEST_ASSERT_EQUAL(BLOCK_OK, consensus_check_header_context(&header, &parent, 0xFFFFFFFF, true));
}

TEST_CASE("poprawna coinbase przechodzi kontrole", "[consensus]") {
    make_coinbase_block(&s_block, 11);
    TEST_ASSERT_EQUAL(BLOCK_OK, consensus_check_transactions(&s_block));
}

TEST_CASE("blok bez transakcji jest odrzucany", "[consensus]") {
    make_coinbase_block(&s_block, 11);
    s_block.tx_count = 0;
    TEST_ASSERT_EQUAL(BLOCK_ERR_NO_TX, consensus_check_transactions(&s_block));
}

TEST_CASE("kazde naruszenie regul coinbase jest odrzucane", "[consensus]") {
    make_coinbase_block(&s_block, 11);
    s_block.txs[0].type = KRST_TX_TRANSFER;
    TEST_ASSERT_EQUAL(BLOCK_ERR_COINBASE, consensus_check_transactions(&s_block));

    make_coinbase_block(&s_block, 11);
    s_block.txs[0].nonce = 12;
    TEST_ASSERT_EQUAL(BLOCK_ERR_COINBASE, consensus_check_transactions(&s_block));

    make_coinbase_block(&s_block, 11);
    s_block.txs[0].amount = CONSENSUS_BLOCK_REWARD + 1;
    TEST_ASSERT_EQUAL(BLOCK_ERR_COINBASE, consensus_check_transactions(&s_block));
    s_block.txs[0].amount = CONSENSUS_BLOCK_REWARD - 1;
    TEST_ASSERT_EQUAL(BLOCK_ERR_COINBASE, consensus_check_transactions(&s_block));

    make_coinbase_block(&s_block, 11);
    s_block.txs[0].sender[32] = 0x01;
    TEST_ASSERT_EQUAL(BLOCK_ERR_COINBASE, consensus_check_transactions(&s_block));

    make_coinbase_block(&s_block, 11);
    s_block.txs[0].signature[63] = 0x01;
    TEST_ASSERT_EQUAL(BLOCK_ERR_COINBASE, consensus_check_transactions(&s_block));

    make_coinbase_block(&s_block, 11);
    s_block.txs[0].recipient[0] = 0x04;
    TEST_ASSERT_EQUAL(BLOCK_ERR_COINBASE, consensus_check_transactions(&s_block));
}

TEST_CASE("druga coinbase w bloku jest odrzucana", "[consensus]") {
    make_coinbase_block(&s_block, 11);
    make_coinbase(&s_block.txs[1], 11);
    s_block.tx_count = 2;
    TEST_ASSERT_EQUAL(BLOCK_ERR_COINBASE, consensus_check_transactions(&s_block));
}

TEST_CASE("przelew w etapie 2 jest odrzucany", "[consensus]") {
    make_coinbase_block(&s_block, 11);
    s_block.txs[1].type = KRST_TX_TRANSFER;
    s_block.tx_count = 2;
    TEST_ASSERT_EQUAL(BLOCK_ERR_TX_UNSUPPORTED, consensus_check_transactions(&s_block));
}
