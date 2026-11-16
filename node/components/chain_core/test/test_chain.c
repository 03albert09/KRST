#include <string.h>
#include "unity.h"
#include "sdkconfig.h"
#include "block_store.h"
#include "chain.h"
#include "consensus.h"
#include "chain_test_helpers.h"

#define NOW 1800000000u

static block_t s_block;
static block_t s_other;

// Tworzy dziecko aktualnego tipa, jeszcze bez przekazania do lancucha
static void make_tip_child(block_t *block, uint8_t variant) {
    chain_tip_t tip;
    chain_get_tip(&tip);
    th_make_child(block, tip.hash, tip.height, tip.timestamp, variant);
}

// Tworzy dziecko tipa i sprawdza, ze zostalo nowym tipem
static void accept_tip_child(block_t *block, uint8_t variant) {
    make_tip_child(block, variant);
    TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, chain_accept_block(block, NOW, true, NULL));
}

// Blok musi zostac odrzucony z danym kodem i nie moze niczego zmienic
static void assert_rejected(const block_t *block, block_result_t expected, uint32_t now, bool synced) {
    chain_tip_t before, after;
    chain_get_tip(&before);

    block_result_t reason = BLOCK_OK;
    TEST_ASSERT_EQUAL_STRING(chain_result_str(CHAIN_INVALID),
                             chain_result_str(chain_accept_block(block, now, synced, &reason)));
    TEST_ASSERT_EQUAL_STRING(block_result_str(expected), block_result_str(reason));

    chain_get_tip(&after);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(before.hash, after.hash, KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_UINT16(before.block_count, after.block_count);
}

TEST_CASE("nowy lancuch zawiera tylko genesis", "[chain]") {
    th_fresh_chain();

    chain_tip_t tip;
    uint8_t genesis_hash[KRST_HASH_SIZE];
    chain_get_tip(&tip);
    th_genesis_hash(genesis_hash);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(genesis_hash, tip.hash, KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_UINT32(0, tip.height);
    TEST_ASSERT_EQUAL_UINT16(1, tip.block_count);
}

TEST_CASE("poprawne bloki przedluzaja lancuch, a praca sie sumuje", "[chain]") {
    th_fresh_chain();

    chain_tip_t tip;
    chain_get_tip(&tip);
    uint64_t work = tip.cumulative_work;
    const uint64_t block_work = consensus_block_work(CONFIG_KRST_POW_TARGET);

    for (uint32_t height = 1; height <= 3; height++) {
        accept_tip_child(&s_block, 0);

        uint8_t hash[KRST_HASH_SIZE];
        block_header_hash(&s_block.header, hash);
        work += block_work;

        chain_get_tip(&tip);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(hash, tip.hash, KRST_HASH_SIZE);
        TEST_ASSERT_EQUAL_UINT32(height, tip.height);
        TEST_ASSERT_EQUAL_UINT64(work, tip.cumulative_work);
        TEST_ASSERT_EQUAL_UINT32(s_block.header.timestamp, tip.timestamp);
    }
}

TEST_CASE("znany blok jest duplikatem i niczego nie zmienia", "[chain]") {
    th_fresh_chain();
    accept_tip_child(&s_block, 0);

    chain_tip_t before, after;
    chain_get_tip(&before);
    TEST_ASSERT_EQUAL(CHAIN_DUPLICATE, chain_accept_block(&s_block, NOW, true, NULL));
    chain_get_tip(&after);
    TEST_ASSERT_EQUAL_UINT16(before.block_count, after.block_count);
}

TEST_CASE("blok z nieznanym rodzicem jest sierota", "[chain]") {
    th_fresh_chain();

    const uint8_t unknown_parent[KRST_HASH_SIZE] = { 0xDE, 0xAD };
    th_make_child(&s_block, unknown_parent, 5, CONSENSUS_GENESIS_TIMESTAMP, 0);
    TEST_ASSERT_EQUAL(CHAIN_ORPHAN, chain_accept_block(&s_block, NOW, true, NULL));

    chain_tip_t tip;
    chain_get_tip(&tip);
    TEST_ASSERT_EQUAL_UINT16(1, tip.block_count);
}

TEST_CASE("blok bez pracy jest odrzucany", "[chain]") {
    th_fresh_chain();
    make_tip_child(&s_block, 0);
    th_break_pow(&s_block);
    assert_rejected(&s_block, BLOCK_ERR_POW, NOW, true);
}

TEST_CASE("zbyt latwy prog jest odrzucany mimo spelnionego PoW", "[chain]") {
    th_fresh_chain();
    make_tip_child(&s_block, 0);
    s_block.header.target = CONSENSUS_GENESIS_TARGET;
    th_finish(&s_block);
    assert_rejected(&s_block, BLOCK_ERR_TARGET, NOW, true);
}

TEST_CASE("zla wysokosc jest odrzucana", "[chain]") {
    th_fresh_chain();
    make_tip_child(&s_block, 0);
    s_block.header.height += 1;
    s_block.txs[0].nonce = s_block.header.height;
    th_finish(&s_block);
    assert_rejected(&s_block, BLOCK_ERR_HEIGHT, NOW, true);
}

TEST_CASE("blok niepozniejszy od rodzica jest odrzucany", "[chain]") {
    th_fresh_chain();
    make_tip_child(&s_block, 0);
    s_block.header.timestamp = CONSENSUS_GENESIS_TIMESTAMP;
    th_finish(&s_block);
    assert_rejected(&s_block, BLOCK_ERR_TIMESTAMP, NOW, true);
}

TEST_CASE("blok z przyszlosci jest odrzucany tylko przy pewnym zegarze", "[chain]") {
    th_fresh_chain();
    make_tip_child(&s_block, 0);

    const uint32_t now = s_block.header.timestamp - CONSENSUS_MAX_FUTURE_SEC - 1;
    assert_rejected(&s_block, BLOCK_ERR_TIMESTAMP, now, true);
    TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, chain_accept_block(&s_block, now, false, NULL));
}

TEST_CASE("podmiana transakcji po wykopaniu jest odrzucana", "[chain]") {
    th_fresh_chain();
    make_tip_child(&s_block, 0);

    s_block.txs[0].recipient[1] ^= 0xFF;
    assert_rejected(&s_block, BLOCK_ERR_MERKLE, NOW, true);
}

TEST_CASE("blok bez transakcji jest odrzucany przez lancuch", "[chain]") {
    th_fresh_chain();
    make_tip_child(&s_block, 0);
    s_block.tx_count = 0;
    th_finish(&s_block);
    assert_rejected(&s_block, BLOCK_ERR_NO_TX, NOW, true);
}

TEST_CASE("zawyzona nagroda jest odrzucana", "[chain]") {
    th_fresh_chain();
    make_tip_child(&s_block, 0);
    s_block.txs[0].amount = CONSENSUS_BLOCK_REWARD + 1;
    th_finish(&s_block);
    assert_rejected(&s_block, BLOCK_ERR_COINBASE, NOW, true);
}

TEST_CASE("przelew w bloku jest odrzucany przez lancuch", "[chain]") {
    th_fresh_chain();
    make_tip_child(&s_block, 0);
    s_block.tx_count = 2;
    s_block.txs[1].type = KRST_TX_TRANSFER;
    th_finish(&s_block);
    assert_rejected(&s_block, BLOCK_ERR_TX_UNSUPPORTED, NOW, true);
}

TEST_CASE("drugi blok na tej samej wysokosci trafia na boczna galaz", "[chain]") {
    th_fresh_chain();

    uint8_t genesis_hash[KRST_HASH_SIZE];
    th_genesis_hash(genesis_hash);

    accept_tip_child(&s_block, 0);
    chain_tip_t tip_before, tip_after;
    chain_get_tip(&tip_before);

    th_make_child(&s_other, genesis_hash, 0, CONSENSUS_GENESIS_TIMESTAMP, 1);
    TEST_ASSERT_EQUAL(CHAIN_SIDE_BRANCH, chain_accept_block(&s_other, NOW, true, NULL));

    chain_get_tip(&tip_after);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tip_before.hash, tip_after.hash, KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_UINT16(tip_before.block_count + 1, tip_after.block_count);

    uint8_t side_hash[KRST_HASH_SIZE];
    block_header_hash(&s_other.header, side_hash);
    th_make_child(&s_block, side_hash, 1, s_other.header.timestamp, 0);
    TEST_ASSERT_EQUAL(CHAIN_SIDE_BRANCH, chain_accept_block(&s_block, NOW, true, NULL));

    chain_get_tip(&tip_after);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tip_before.hash, tip_after.hash, KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_UINT32(1, tip_after.height);
}

TEST_CASE("lancuch i boczne galezie sa odtwarzane po restarcie", "[chain]") {
    th_fresh_chain();

    uint8_t genesis_hash[KRST_HASH_SIZE];
    th_genesis_hash(genesis_hash);

    accept_tip_child(&s_block, 0);
    accept_tip_child(&s_block, 0);
    th_make_child(&s_other, genesis_hash, 0, CONSENSUS_GENESIS_TIMESTAMP, 1);
    TEST_ASSERT_EQUAL(CHAIN_SIDE_BRANCH, chain_accept_block(&s_other, NOW, true, NULL));

    chain_tip_t before, after;
    chain_get_tip(&before);

    TEST_ASSERT_EQUAL(ESP_OK, chain_init());
    chain_get_tip(&after);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(before.hash, after.hash, KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_UINT32(2, after.height);
    TEST_ASSERT_EQUAL_UINT16(before.block_count, after.block_count);
    TEST_ASSERT_EQUAL_UINT64(before.cumulative_work, after.cumulative_work);

    TEST_ASSERT_EQUAL(CHAIN_DUPLICATE, chain_accept_block(&s_other, NOW, true, NULL));
    accept_tip_child(&s_block, 0);
}

TEST_CASE("niepoprawny blok w dzienniku nie trafia do lancucha", "[chain]") {
    th_fresh_chain();
    accept_tip_child(&s_block, 0);

    chain_tip_t before, after;
    chain_get_tip(&before);

    make_tip_child(&s_other, 0);
    s_other.txs[0].amount = CONSENSUS_BLOCK_REWARD + 1;
    th_finish(&s_other);
    TEST_ASSERT_EQUAL(ESP_OK, block_store_append(&s_other, NULL));

    TEST_ASSERT_EQUAL(ESP_OK, chain_init());
    chain_get_tip(&after);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(before.hash, after.hash, KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_UINT16(before.block_count, after.block_count);
}

TEST_CASE("zmiana sieci kasuje lancuch", "[chain]") {
    th_fresh_chain();
    accept_tip_child(&s_block, 0);

    const uint8_t other_network[KRST_HASH_SIZE] = { 0x77 };
    TEST_ASSERT_EQUAL(ESP_OK, block_store_open(other_network, NULL, NULL));

    TEST_ASSERT_EQUAL(ESP_OK, chain_init());
    chain_tip_t tip;
    chain_get_tip(&tip);
    TEST_ASSERT_EQUAL_UINT32(0, tip.height);
    TEST_ASSERT_EQUAL_UINT16(1, tip.block_count);
}

TEST_CASE("pelny indeks odrzuca kolejny blok i nie uszkadza lancucha", "[chain]") {
    th_fresh_chain();

    for (int i = 1; i < CHAIN_MAX_BLOCKS; i++) {
        accept_tip_child(&s_block, 0);
    }

    chain_tip_t before, after;
    chain_get_tip(&before);
    TEST_ASSERT_EQUAL_UINT16(CHAIN_MAX_BLOCKS, before.block_count);
    TEST_ASSERT_EQUAL_UINT32(CHAIN_MAX_BLOCKS - 1, before.height);

    make_tip_child(&s_block, 0);
    TEST_ASSERT_EQUAL(CHAIN_FULL, chain_accept_block(&s_block, NOW, true, NULL));

    chain_get_tip(&after);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(before.hash, after.hash, KRST_HASH_SIZE);

    TEST_ASSERT_EQUAL(ESP_OK, chain_init());
    chain_get_tip(&after);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(before.hash, after.hash, KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_UINT16(CHAIN_MAX_BLOCKS, after.block_count);
}

TEST_CASE("kazdy wynik ma czytelna nazwe", "[chain]") {
    TEST_ASSERT_EQUAL_STRING("BLOCK_ERR_MERKLE", block_result_str(BLOCK_ERR_MERKLE));
    TEST_ASSERT_EQUAL_STRING("BLOCK_ERR_TX_UNSUPPORTED", block_result_str(BLOCK_ERR_TX_UNSUPPORTED));
    TEST_ASSERT_EQUAL_STRING("CHAIN_ORPHAN", chain_result_str(CHAIN_ORPHAN));
    TEST_ASSERT_EQUAL_STRING("CHAIN_STORE_ERROR", chain_result_str(CHAIN_STORE_ERROR));
}
