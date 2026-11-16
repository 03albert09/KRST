#include <string.h>
#include "unity.h"
#include "chain.h"
#include "consensus.h"
#include "ledger.h"
#include "chain_test_helpers.h"

#define NOW 1800000000u

static block_t s_block;
static block_t s_other;

// Adres, na ktory th_make_child wysyla nagrode dla danego wariantu
static void variant_address(uint8_t address[KRST_PUBKEY_SIZE], uint8_t variant) {
    address[0] = 0x02;
    memset(address + 1, variant + 1, 32);
}

// Dopisuje dziecko tipa z nagroda dla danego wariantu
static chain_result_t accept_tip_child(uint8_t variant) {
    chain_tip_t tip;
    chain_get_tip(&tip);
    th_make_child(&s_block, tip.hash, tip.height, tip.timestamp, variant);
    return chain_accept_block(&s_block, NOW, true, NULL);
}

TEST_CASE("nieznane konto ma saldo zero", "[ledger]") {
    th_fresh_chain();
    uint8_t address[KRST_PUBKEY_SIZE];
    variant_address(address, 0);
    TEST_ASSERT_EQUAL_UINT64(0, ledger_get_balance(address));
}

TEST_CASE("nagrody sumuja sie osobno dla kazdego konta", "[ledger]") {
    th_fresh_chain();

    TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, accept_tip_child(0));
    TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, accept_tip_child(1));
    TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, accept_tip_child(0));

    uint8_t first[KRST_PUBKEY_SIZE], second[KRST_PUBKEY_SIZE];
    variant_address(first, 0);
    variant_address(second, 1);
    TEST_ASSERT_EQUAL_UINT64(2 * CONSENSUS_BLOCK_REWARD, ledger_get_balance(first));
    TEST_ASSERT_EQUAL_UINT64(CONSENSUS_BLOCK_REWARD, ledger_get_balance(second));
}

TEST_CASE("odrzucony blok nie zmienia salda", "[ledger]") {
    th_fresh_chain();

    chain_tip_t tip;
    chain_get_tip(&tip);
    th_make_child(&s_block, tip.hash, tip.height, tip.timestamp, 0);
    s_block.txs[0].amount = CONSENSUS_BLOCK_REWARD + 1;
    th_finish(&s_block);
    TEST_ASSERT_EQUAL(CHAIN_INVALID, chain_accept_block(&s_block, NOW, true, NULL));

    uint8_t address[KRST_PUBKEY_SIZE];
    variant_address(address, 0);
    TEST_ASSERT_EQUAL_UINT64(0, ledger_get_balance(address));
}

TEST_CASE("boczna galaz nie zmienia salda", "[ledger]") {
    th_fresh_chain();

    uint8_t genesis_hash[KRST_HASH_SIZE];
    th_genesis_hash(genesis_hash);

    TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, accept_tip_child(0));
    th_make_child(&s_other, genesis_hash, 0, CONSENSUS_GENESIS_TIMESTAMP, 1);
    TEST_ASSERT_EQUAL(CHAIN_SIDE_BRANCH, chain_accept_block(&s_other, NOW, true, NULL));

    uint8_t side_miner[KRST_PUBKEY_SIZE];
    variant_address(side_miner, 1);
    TEST_ASSERT_EQUAL_UINT64(0, ledger_get_balance(side_miner));
}

TEST_CASE("salda sa odtwarzane po restarcie bez bocznych galezi", "[ledger]") {
    th_fresh_chain();

    uint8_t genesis_hash[KRST_HASH_SIZE];
    th_genesis_hash(genesis_hash);

    TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, accept_tip_child(0));
    TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, accept_tip_child(0));
    th_make_child(&s_other, genesis_hash, 0, CONSENSUS_GENESIS_TIMESTAMP, 1);
    TEST_ASSERT_EQUAL(CHAIN_SIDE_BRANCH, chain_accept_block(&s_other, NOW, true, NULL));

    TEST_ASSERT_EQUAL(ESP_OK, chain_init());

    uint8_t miner[KRST_PUBKEY_SIZE], side_miner[KRST_PUBKEY_SIZE];
    variant_address(miner, 0);
    variant_address(side_miner, 1);
    TEST_ASSERT_EQUAL_UINT64(2 * CONSENSUS_BLOCK_REWARD, ledger_get_balance(miner));
    TEST_ASSERT_EQUAL_UINT64(0, ledger_get_balance(side_miner));
}

TEST_CASE("skasowanie lancucha zeruje salda", "[ledger]") {
    th_fresh_chain();
    TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, accept_tip_child(0));

    TEST_ASSERT_EQUAL(ESP_OK, chain_reset());

    uint8_t address[KRST_PUBKEY_SIZE];
    variant_address(address, 0);
    TEST_ASSERT_EQUAL_UINT64(0, ledger_get_balance(address));
}

TEST_CASE("pelna tabela kont odrzuca tylko nowe konto", "[ledger]") {
    th_fresh_chain();

    for (int i = 0; i < LEDGER_MAX_ACCOUNTS; i++) {
        TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, accept_tip_child((uint8_t)i));
    }

    chain_tip_t before, after;
    chain_get_tip(&before);
    TEST_ASSERT_EQUAL(CHAIN_FULL, accept_tip_child(LEDGER_MAX_ACCOUNTS));
    chain_get_tip(&after);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(before.hash, after.hash, KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_UINT16(before.block_count, after.block_count);

    TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, accept_tip_child(0));

    uint8_t address[KRST_PUBKEY_SIZE];
    variant_address(address, 0);
    TEST_ASSERT_EQUAL_UINT64(2 * CONSENSUS_BLOCK_REWARD, ledger_get_balance(address));
}
