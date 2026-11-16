#include <string.h>
#include "unity.h"
#include "chain.h"
#include "consensus.h"
#include "evil_block.h"
#include "miner.h"
#include "chain_test_helpers.h"

#define NOW 1800000000u

static block_t s_block;

// Blok z wada, gotowy do wyslania, tak jak robi to komenda evil
static void build_evil_block(evil_block_kind_t kind) {
    th_fresh_chain();

    chain_tip_t tip;
    uint8_t payout[KRST_PUBKEY_SIZE];
    chain_get_tip(&tip);
    payout[0] = 0x02;
    memset(payout + 1, 0x11, KRST_PUBKEY_SIZE - 1);

    evil_block_prepare(&s_block, kind, &tip, payout, NOW);
    if (evil_block_needs_mining(kind)) {
        TEST_ASSERT_TRUE(miner_search(&s_block.header, 1000000));
    }
}

// Sprawdza, ze blok zostal odrzucony z danym kodem i tip sie nie zmienil
static void assert_rejected_with(block_result_t expected) {
    block_result_t reason = BLOCK_OK;
    TEST_ASSERT_EQUAL(CHAIN_INVALID, chain_accept_block(&s_block, NOW, true, &reason));
    TEST_ASSERT_EQUAL(expected, reason);

    chain_tip_t tip;
    chain_get_tip(&tip);
    TEST_ASSERT_EQUAL_UINT32(0, tip.height);
}

TEST_CASE("zly PoW daje BLOCK_ERR_POW", "[evil]") {
    build_evil_block(EVIL_BLOCK_POW);
    assert_rejected_with(BLOCK_ERR_POW);
}

TEST_CASE("zly korzen Merkle daje BLOCK_ERR_MERKLE", "[evil]") {
    build_evil_block(EVIL_BLOCK_MERKLE);
    assert_rejected_with(BLOCK_ERR_MERKLE);
}

TEST_CASE("latwiejszy prog daje BLOCK_ERR_TARGET mimo spelnionego PoW", "[evil]") {
    build_evil_block(EVIL_BLOCK_TARGET);

    uint8_t hash[KRST_HASH_SIZE];
    block_header_hash(&s_block.header, hash);
    TEST_ASSERT_TRUE(consensus_check_pow(hash, s_block.header.target));
    assert_rejected_with(BLOCK_ERR_TARGET);
}

TEST_CASE("zla wysokosc daje BLOCK_ERR_HEIGHT i to jedyna wada", "[evil]") {
    build_evil_block(EVIL_BLOCK_HEIGHT);

    TEST_ASSERT_EQUAL(BLOCK_OK, block_check_structure(&s_block));
    TEST_ASSERT_EQUAL(BLOCK_OK, consensus_check_transactions(&s_block));
    assert_rejected_with(BLOCK_ERR_HEIGHT);
}

TEST_CASE("czas rodzica daje BLOCK_ERR_TIMESTAMP", "[evil]") {
    build_evil_block(EVIL_BLOCK_TIMESTAMP);
    assert_rejected_with(BLOCK_ERR_TIMESTAMP);
}

TEST_CASE("za duza nagroda daje BLOCK_ERR_COINBASE, a nie blad Merkle", "[evil]") {
    build_evil_block(EVIL_BLOCK_COINBASE);

    TEST_ASSERT_EQUAL(BLOCK_OK, block_check_structure(&s_block));
    assert_rejected_with(BLOCK_ERR_COINBASE);
}

TEST_CASE("nieznany rodzic daje CHAIN_ORPHAN bez zapisu bloku", "[evil]") {
    build_evil_block(EVIL_BLOCK_ORPHAN);

    TEST_ASSERT_EQUAL(CHAIN_ORPHAN, chain_accept_block(&s_block, NOW, true, NULL));

    chain_tip_t tip;
    chain_get_tip(&tip);
    TEST_ASSERT_EQUAL_UINT32(0, tip.height);
}

TEST_CASE("ramka krotsza o bajt daje BLOCK_ERR_SIZE", "[evil]") {
    build_evil_block(EVIL_BLOCK_FORMAT);

    static block_t parsed;
    uint32_t length = evil_block_wire_length(&s_block, EVIL_BLOCK_FORMAT);
    TEST_ASSERT_EQUAL_UINT32(block_serialized_size(&s_block) - 1, length);
    TEST_ASSERT_EQUAL(BLOCK_ERR_SIZE, block_parse((const uint8_t *)&s_block, length, &parsed));
}
