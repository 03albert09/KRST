#include <string.h>
#include "unity.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "chain.h"
#include "consensus.h"
#include "ledger.h"
#include "miner.h"
#include "chain_test_helpers.h"

#define NOW 1800000000u

static block_t s_block;

// Adres nagrod wypelniony podanym bajtem
static void make_payout(uint8_t payout[KRST_PUBKEY_SIZE], uint8_t fill) {
    payout[0] = 0x03;
    memset(payout + 1, fill, 32);
}

// Czeka do 20 s, az gornik sie zatrzyma
static void wait_until_stopped(void) {
    for (int waited_ms = 0; waited_ms < 20000 && miner_is_running(); waited_ms += 20) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    TEST_ASSERT_FALSE(miner_is_running());
}

TEST_CASE("kandydat na blok ma poprawne pola i coinbase na adres portfela", "[miner]") {
    th_fresh_chain();

    chain_tip_t tip;
    uint8_t payout[KRST_PUBKEY_SIZE];
    chain_get_tip(&tip);
    make_payout(payout, 0xAB);

    miner_build_block(&s_block, &tip, payout, NOW);

    TEST_ASSERT_EQUAL_UINT32(1, s_block.header.height);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tip.hash, s_block.header.prev_hash, KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_UINT32(NOW, s_block.header.timestamp);
    TEST_ASSERT_EQUAL_UINT16(1, s_block.tx_count);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(payout, s_block.txs[0].recipient, KRST_PUBKEY_SIZE);
    TEST_ASSERT_EQUAL(BLOCK_OK, block_check_structure(&s_block));
    TEST_ASSERT_EQUAL(BLOCK_OK, consensus_check_transactions(&s_block));
}

TEST_CASE("bez zsynchronizowanego zegara czas bloku jest pozniejszy od rodzica", "[miner]") {
    th_fresh_chain();

    chain_tip_t tip;
    uint8_t payout[KRST_PUBKEY_SIZE];
    chain_get_tip(&tip);
    make_payout(payout, 0xAB);

    miner_build_block(&s_block, &tip, payout, 5);
    TEST_ASSERT_EQUAL_UINT32(tip.timestamp + 1, s_block.header.timestamp);
}

TEST_CASE("znaleziony nonce spelnia PoW", "[miner]") {
    th_fresh_chain();

    chain_tip_t tip;
    uint8_t payout[KRST_PUBKEY_SIZE];
    chain_get_tip(&tip);
    make_payout(payout, 0xAB);
    miner_build_block(&s_block, &tip, payout, NOW);

    TEST_ASSERT_TRUE(miner_search(&s_block.header, 1000000));

    uint8_t hash[KRST_HASH_SIZE];
    block_header_hash(&s_block.header, hash);
    TEST_ASSERT_TRUE(consensus_check_pow(hash, s_block.header.target));
}

TEST_CASE("wyszukiwanie respektuje limit i wykrywa koniec zakresu nonce", "[miner]") {
    block_header_t header;
    memset(&header, 0, sizeof(header));

    TEST_ASSERT_FALSE(miner_search(&header, 10));
    TEST_ASSERT_EQUAL_UINT32(10, header.nonce);

    header.nonce = 0xFFFFFFFE;
    TEST_ASSERT_FALSE(miner_search(&header, 10));
    TEST_ASSERT_EQUAL_UINT32(0, header.nonce);
}

TEST_CASE("petla kopania znajduje nonce dla aktualnego tipa", "[miner]") {
    th_fresh_chain();

    chain_tip_t tip;
    uint8_t payout[KRST_PUBKEY_SIZE];
    chain_get_tip(&tip);
    make_payout(payout, 0xAB);
    miner_build_block(&s_block, &tip, payout, NOW);

    TEST_ASSERT_TRUE(miner_mine(&s_block, tip.hash, NULL));

    uint8_t hash[KRST_HASH_SIZE];
    block_header_hash(&s_block.header, hash);
    TEST_ASSERT_TRUE(consensus_check_pow(hash, s_block.header.target));
}

TEST_CASE("petla kopania przerywa prace po zmianie tipa", "[miner]") {
    th_fresh_chain();
    memset(&s_block, 0, sizeof(s_block));

    const uint8_t old_tip[KRST_HASH_SIZE] = { 0x42 };
    TEST_ASSERT_FALSE(miner_mine(&s_block, old_tip, NULL));
    TEST_ASSERT_GREATER_THAN_UINT32(0, s_block.header.nonce);
}

TEST_CASE("petla kopania nie zaczyna pracy po prosbie o zatrzymanie", "[miner]") {
    th_fresh_chain();
    memset(&s_block, 0, sizeof(s_block));

    chain_tip_t tip;
    chain_get_tip(&tip);
    volatile bool stop = true;
    TEST_ASSERT_FALSE(miner_mine(&s_block, tip.hash, &stop));
    TEST_ASSERT_EQUAL_UINT32(0, s_block.header.nonce);
}

TEST_CASE("wykopany blok przechodzi pelna walidacje lancucha", "[miner]") {
    th_fresh_chain();

    chain_tip_t tip;
    uint8_t payout[KRST_PUBKEY_SIZE];
    chain_get_tip(&tip);
    make_payout(payout, 0xAB);
    miner_build_block(&s_block, &tip, payout, NOW);
    TEST_ASSERT_TRUE(miner_search(&s_block.header, 1000000));

    TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, chain_accept_block(&s_block, NOW, true, NULL));
    TEST_ASSERT_EQUAL_UINT64(CONSENSUS_BLOCK_REWARD, ledger_get_balance(payout));
}

TEST_CASE("pomiar szybkosci kopania zwraca niezerowy wynik", "[miner]") {
    TEST_ASSERT_GREATER_THAN_UINT32(0, miner_measure_hashrate(200));
}

TEST_CASE("gornik w tle kopie bloki, placi na adres portfela i daje sie zatrzymac", "[miner]") {
    th_prepare_chain_task();

    uint8_t payout[KRST_PUBKEY_SIZE];
    make_payout(payout, 0xCD);
    TEST_ASSERT_EQUAL(ESP_OK, miner_start(payout));
    TEST_ASSERT_TRUE(miner_is_running());
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, miner_start(payout));

    chain_tip_t tip;
    for (int waited_ms = 0; waited_ms < 20000; waited_ms += 20) {
        chain_get_tip(&tip);
        if (tip.height >= 3) break;
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    miner_stop();
    wait_until_stopped();
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(3, tip.height);

    vTaskDelay(pdMS_TO_TICKS(500));
    chain_tip_t stopped;
    chain_get_tip(&stopped);
    TEST_ASSERT_EQUAL_UINT64(stopped.height * CONSENSUS_BLOCK_REWARD, ledger_get_balance(payout));

    vTaskDelay(pdMS_TO_TICKS(500));
    chain_tip_t later;
    chain_get_tip(&later);
    TEST_ASSERT_EQUAL_UINT32(stopped.height, later.height);
}

TEST_CASE("gornik zatrzymuje sie sam, gdy lancuch nie przyjmuje blokow", "[miner]") {
    th_prepare_chain_task();

    for (int i = 0; i < LEDGER_MAX_ACCOUNTS; i++) {
        chain_tip_t tip;
        chain_get_tip(&tip);
        th_make_child(&s_block, tip.hash, tip.height, tip.timestamp, (uint8_t)i);
        TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, chain_accept_block(&s_block, NOW, true, NULL));
    }

    chain_tip_t before;
    chain_get_tip(&before);

    uint8_t payout[KRST_PUBKEY_SIZE];
    make_payout(payout, 0xEF);
    TEST_ASSERT_EQUAL(ESP_OK, miner_start(payout));
    wait_until_stopped();

    chain_tip_t after;
    chain_get_tip(&after);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(before.hash, after.hash, KRST_HASH_SIZE);
}
