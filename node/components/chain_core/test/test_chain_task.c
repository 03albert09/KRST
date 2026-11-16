#include <stdlib.h>
#include <string.h>
#include "unity.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "chain_task.h"
#include "chain_test_helpers.h"

typedef struct {
    uint32_t height;
    chain_result_t result;
    block_result_t reason;
    p2p_peer_ref_t source;
} recorded_result_t;

static SemaphoreHandle_t s_done = NULL;
static recorded_result_t s_results[4];
static volatile int s_result_count;

static chain_task_result_fn s_forward = NULL;
static volatile chain_task_tick_fn s_tick_forward = NULL;

// Ustawia funkcje, ktorej przekazywane sa wyniki przetwarzania blokow
void th_set_result_forward(chain_task_result_fn forward) {
    s_forward = forward;
}

// Ustawia funkcje, ktorej przekazywane sa okresowe sprawdzenia
void th_set_tick_forward(chain_task_tick_fn forward) {
    s_tick_forward = forward;
}

// Przekazuje okresowe sprawdzenie dalej, jesli ustawiono odbiorce
static void on_tick(TickType_t now) {
    chain_task_tick_fn forward = s_tick_forward;
    if (forward != NULL) {
        forward(now);
    }
}

// Sygnalizuje, ze zadanie lancucha doszlo do tej pracy
static void signal_idle(void *arg, p2p_peer_ref_t source) {
    (void)source;
    xSemaphoreGive((SemaphoreHandle_t)arg);
}

// Czeka, az zadanie lancucha przetworzy wszystko z kolejki
void th_wait_chain_idle(void) {
    SemaphoreHandle_t idle = xSemaphoreCreateBinary();
    TEST_ASSERT_NOT_NULL(idle);
    TEST_ASSERT_TRUE(chain_task_post_work(signal_idle, idle, CHAIN_SOURCE_LOCAL, pdMS_TO_TICKS(5000)));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(idle, pdMS_TO_TICKS(10000)));
    vSemaphoreDelete(idle);
}

// Zapisuje wynik przetworzenia bloku i przekazuje go dalej
static void on_result(const block_t *block, chain_result_t result, block_result_t reason,
                      p2p_peer_ref_t source, bool relay) {
    if (s_forward != NULL) {
        s_forward(block, result, reason, source, relay);
    }
    if (s_result_count < (int)(sizeof(s_results) / sizeof(s_results[0]))) {
        recorded_result_t *record = &s_results[s_result_count];
        record->height = block->header.height;
        record->result = result;
        record->reason = reason;
        record->source = source;
        s_result_count++;
    }
    xSemaphoreGive(s_done);
}

// Zegar w testach udaje brak synchronizacji SNTP
static bool clock_not_synced(void) {
    return false;
}

// Przygotowuje swiezy lancuch i zadanie lancucha. Zadanie startuje raz na cale uruchomienie testow.
void th_prepare_chain_task(void) {
    th_fresh_chain();

    if (s_done == NULL) {
        s_done = xSemaphoreCreateCounting(16, 0);
        TEST_ASSERT_NOT_NULL(s_done);

        chain_task_config_t config = { .clock_synced = clock_not_synced, .on_result = on_result, .on_tick = on_tick };
        TEST_ASSERT_EQUAL(ESP_OK, chain_task_start(&config));
    }

    while (xSemaphoreTake(s_done, 0) == pdTRUE) {
    }
    s_result_count = 0;
    s_forward = NULL;
    s_tick_forward = NULL;
}

// Czeka na podana liczbe wynikow z zadania lancucha
static void wait_for_results(int count) {
    for (int i = 0; i < count; i++) {
        TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(s_done, pdMS_TO_TICKS(5000)));
    }
    TEST_ASSERT_EQUAL(count, s_result_count);
}

// Alokuje i buduje dziecko podanego rodzica
static block_t *new_tip_child(const uint8_t parent_hash[KRST_HASH_SIZE], uint32_t parent_height,
                              uint32_t parent_timestamp) {
    block_t *block = malloc(sizeof(block_t));
    TEST_ASSERT_NOT_NULL(block);
    th_make_child(block, parent_hash, parent_height, parent_timestamp, 0);
    return block;
}

TEST_CASE("blok z kolejki przedluza lancuch i przekazuje zrodlo", "[chain_task]") {
    th_prepare_chain_task();

    chain_tip_t tip;
    chain_get_tip(&tip);
    block_t *block = new_tip_child(tip.hash, tip.height, tip.timestamp);

    const p2p_peer_ref_t source = { .slot = 2, .conn_id = 77 };
    TEST_ASSERT_TRUE(chain_task_submit_block(block, source, true, pdMS_TO_TICKS(1000)));
    wait_for_results(1);

    TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, s_results[0].result);
    TEST_ASSERT_EQUAL(BLOCK_OK, s_results[0].reason);
    TEST_ASSERT_EQUAL_INT8(2, s_results[0].source.slot);
    TEST_ASSERT_EQUAL_UINT32(77, s_results[0].source.conn_id);

    chain_get_tip(&tip);
    TEST_ASSERT_EQUAL_UINT32(1, tip.height);
}

TEST_CASE("zadanie zglasza powod odrzucenia bloku", "[chain_task]") {
    th_prepare_chain_task();

    chain_tip_t tip;
    chain_get_tip(&tip);
    block_t *block = new_tip_child(tip.hash, tip.height, tip.timestamp);
    th_break_pow(block);

    TEST_ASSERT_TRUE(chain_task_submit_block(block, CHAIN_SOURCE_LOCAL, true, pdMS_TO_TICKS(1000)));
    wait_for_results(1);

    TEST_ASSERT_EQUAL(CHAIN_INVALID, s_results[0].result);
    TEST_ASSERT_EQUAL(BLOCK_ERR_POW, s_results[0].reason);
    TEST_ASSERT_EQUAL_INT8(-1, s_results[0].source.slot);

    chain_get_tip(&tip);
    TEST_ASSERT_EQUAL_UINT32(0, tip.height);
}

static volatile int s_tick_count;

// Zlicza okresowe sprawdzenia
static void count_tick(TickType_t now) {
    (void)now;
    s_tick_count++;
}

TEST_CASE("zadanie lancucha wywoluje okresowe sprawdzenie takze bez wiadomosci", "[chain_task]") {
    th_prepare_chain_task();
    s_tick_count = 0;
    th_set_tick_forward(count_tick);

    vTaskDelay(pdMS_TO_TICKS(2 * CHAIN_TASK_TICK_MS + 500));
    th_set_tick_forward(NULL);

    TEST_ASSERT_GREATER_OR_EQUAL_INT(2, s_tick_count);
    TEST_ASSERT_LESS_OR_EQUAL_INT(3, s_tick_count);
}

TEST_CASE("bloki sa przetwarzane w kolejnosci przyjecia", "[chain_task]") {
    th_prepare_chain_task();

    chain_tip_t tip;
    chain_get_tip(&tip);

    uint8_t parent_hash[KRST_HASH_SIZE];
    memcpy(parent_hash, tip.hash, KRST_HASH_SIZE);
    uint32_t parent_height = tip.height;
    uint32_t parent_timestamp = tip.timestamp;

    for (int i = 0; i < 3; i++) {
        block_t *block = new_tip_child(parent_hash, parent_height, parent_timestamp);
        block_header_hash(&block->header, parent_hash);
        parent_height = block->header.height;
        parent_timestamp = block->header.timestamp;
        TEST_ASSERT_TRUE(chain_task_submit_block(block, CHAIN_SOURCE_LOCAL, true, pdMS_TO_TICKS(1000)));
    }
    wait_for_results(3);

    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, s_results[i].result);
        TEST_ASSERT_EQUAL_UINT32(i + 1, s_results[i].height);
    }

    chain_get_tip(&tip);
    TEST_ASSERT_EQUAL_UINT32(3, tip.height);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(parent_hash, tip.hash, KRST_HASH_SIZE);
}
