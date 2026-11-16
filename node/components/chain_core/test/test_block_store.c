#include <string.h>
#include "unity.h"
#include "esp_partition.h"
#include "block_store.h"

#define MAX_VISITED 16

static const uint8_t NETWORK_A[KRST_HASH_SIZE] = { 0xA1 };
static const uint8_t NETWORK_B[KRST_HASH_SIZE] = { 0xB2 };

static block_t s_block;
static block_t s_read_back;

static uint32_t s_visited_heights[MAX_VISITED];
static uint32_t s_visited_offsets[MAX_VISITED];
static int s_visited_count;

// Blok nie musi spelniac regul konsensusu: dziennik sprawdza tylko format
static void make_block(block_t *block, uint32_t height, uint16_t tx_count) {
    memset(block, 0, sizeof(*block));
    block->header.height = height;
    block->tx_count = tx_count;
    for (uint16_t i = 0; i < tx_count; i++) {
        block->txs[i].amount = height + i;
    }
}

// Zapisuje wysokosc i offset kazdego bloku odczytanego z dziennika
static void visit(const block_t *block, uint32_t offset, void *ctx) {
    (void)ctx;
    TEST_ASSERT_LESS_THAN(MAX_VISITED, s_visited_count);
    s_visited_heights[s_visited_count] = block->header.height;
    s_visited_offsets[s_visited_count] = offset;
    s_visited_count++;
}

// Odpowiednik restartu: dziennik czytany od nowa z flasha
static void reopen(void) {
    s_visited_count = 0;
    TEST_ASSERT_EQUAL(ESP_OK, block_store_open(NETWORK_A, visit, NULL));
}

// Formatuje dziennik, zeby test zaczynal od pustego
static void fresh_log(void) {
    reopen();
    TEST_ASSERT_EQUAL(ESP_OK, block_store_format());
    s_visited_count = 0;
}

// Dopisuje blok o podanej wysokosci i zwraca jego offset
static uint32_t append(uint32_t height, uint16_t tx_count) {
    uint32_t offset = 0;
    make_block(&s_block, height, tx_count);
    TEST_ASSERT_EQUAL(ESP_OK, block_store_append(&s_block, &offset));
    return offset;
}

// Rozmiar rekordu w dzienniku dla bloku z podana liczba transakcji
static uint32_t record_size(uint16_t tx_count) {
    make_block(&s_block, 0, tx_count);
    return BLOCK_STORE_RECORD_HEADER_SIZE + (uint32_t)block_serialized_size(&s_block);
}

// Zwraca partycje dziennika blokow
static const esp_partition_t *chain_partition(void) {
    const esp_partition_t *partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x40, "chain");
    TEST_ASSERT_NOT_NULL(partition);
    return partition;
}

TEST_CASE("pusty dziennik nie ma blokow", "[block_store]") {
    fresh_log();
    reopen();
    TEST_ASSERT_EQUAL(0, s_visited_count);
}

TEST_CASE("zapisany blok mozna odczytac bez zmian", "[block_store]") {
    fresh_log();
    uint32_t offset = append(7, 3);
    TEST_ASSERT_EQUAL_UINT32(BLOCK_STORE_FIRST_RECORD, offset);

    memset(&s_read_back, 0xEE, sizeof(s_read_back));
    TEST_ASSERT_EQUAL(ESP_OK, block_store_read(offset, &s_read_back));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(&s_block, &s_read_back, block_serialized_size(&s_block));
}

TEST_CASE("odczyt spod zlego adresu jest odrzucany", "[block_store]") {
    fresh_log();
    uint32_t offset = append(7, 1);
    TEST_ASSERT_EQUAL(ESP_ERR_NOT_FOUND, block_store_read(offset + 1, &s_read_back));
    TEST_ASSERT_EQUAL(ESP_ERR_NOT_FOUND, block_store_read(offset + record_size(1), &s_read_back));
}

TEST_CASE("bloki sa odtwarzane po restarcie w kolejnosci zapisu", "[block_store]") {
    fresh_log();
    append(1, 1);
    append(2, 1);
    append(3, 1);

    reopen();
    TEST_ASSERT_EQUAL(3, s_visited_count);
    TEST_ASSERT_EQUAL_UINT32(1, s_visited_heights[0]);
    TEST_ASSERT_EQUAL_UINT32(2, s_visited_heights[1]);
    TEST_ASSERT_EQUAL_UINT32(3, s_visited_heights[2]);
}

TEST_CASE("po restarcie zapis trafia zaraz za ostatni blok", "[block_store]") {
    fresh_log();
    uint32_t first = append(1, 1);

    reopen();
    uint32_t second = append(2, 1);
    TEST_ASSERT_EQUAL_UINT32(first + record_size(1), second);

    reopen();
    TEST_ASSERT_EQUAL(2, s_visited_count);
}

TEST_CASE("dziennik innej sieci jest kasowany", "[block_store]") {
    fresh_log();
    append(1, 1);

    s_visited_count = 0;
    TEST_ASSERT_EQUAL(ESP_OK, block_store_open(NETWORK_B, visit, NULL));
    TEST_ASSERT_EQUAL(0, s_visited_count);

    s_visited_count = 0;
    TEST_ASSERT_EQUAL(ESP_OK, block_store_open(NETWORK_A, visit, NULL));
    TEST_ASSERT_EQUAL(0, s_visited_count);
}

TEST_CASE("rekord nie przekracza granicy sektora, a dziennik czyta sie dalej", "[block_store]") {
    fresh_log();

    TEST_ASSERT_EQUAL_UINT32(BLOCK_STORE_FIRST_RECORD, append(1, BLOCK_MAX_TX));
    append(2, BLOCK_MAX_TX);
    TEST_ASSERT_EQUAL_UINT32(2 * BLOCK_STORE_SECTOR_SIZE, append(3, BLOCK_MAX_TX));
    append(4, BLOCK_MAX_TX);
    TEST_ASSERT_EQUAL_UINT32(3 * BLOCK_STORE_SECTOR_SIZE, append(5, BLOCK_MAX_TX));

    reopen();
    TEST_ASSERT_EQUAL(5, s_visited_count);
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_EQUAL_UINT32(i + 1, s_visited_heights[i]);
        TEST_ASSERT_EQUAL(ESP_OK, block_store_read(s_visited_offsets[i], &s_read_back));
        TEST_ASSERT_EQUAL_UINT32(i + 1, s_read_back.header.height);
    }
}

TEST_CASE("przerwany zapis nie psuje dziennika", "[block_store]") {
    fresh_log();
    uint32_t first = append(1, 1);
    uint32_t torn_pos = first + record_size(1);

    uint8_t torn[BLOCK_STORE_RECORD_HEADER_SIZE + 8];
    memset(torn, 0x5A, sizeof(torn));
    TEST_ASSERT_EQUAL(ESP_OK, esp_partition_read(chain_partition(), first, torn, 8));
    TEST_ASSERT_EQUAL(ESP_OK, esp_partition_write(chain_partition(), torn_pos, torn, sizeof(torn)));

    reopen();
    TEST_ASSERT_EQUAL(1, s_visited_count);

    uint32_t second = append(2, 1);
    TEST_ASSERT_EQUAL_UINT32(2 * BLOCK_STORE_SECTOR_SIZE, second);

    reopen();
    TEST_ASSERT_EQUAL(2, s_visited_count);
    TEST_ASSERT_EQUAL_UINT32(1, s_visited_heights[0]);
    TEST_ASSERT_EQUAL_UINT32(2, s_visited_heights[1]);
}

TEST_CASE("przerwany zapis samych danych bez naglowka tez jest wykrywany", "[block_store]") {
    fresh_log();
    uint32_t first = append(1, 1);
    uint32_t torn_pos = first + record_size(1);

    const uint8_t partial[8] = { 0x11, 0x22, 0x33, 0x44 };
    TEST_ASSERT_EQUAL(ESP_OK, esp_partition_write(chain_partition(),
                                                  torn_pos + BLOCK_STORE_RECORD_HEADER_SIZE, partial, sizeof(partial)));

    reopen();
    TEST_ASSERT_EQUAL(1, s_visited_count);
    TEST_ASSERT_EQUAL_UINT32(2 * BLOCK_STORE_SECTOR_SIZE, append(2, 1));
}

TEST_CASE("uszkodzone dane rekordu sa wykrywane przez CRC", "[block_store]") {
    fresh_log();
    append(1, 1);
    uint32_t second = append(2, 1);

    const uint8_t zero = 0x00;
    TEST_ASSERT_EQUAL(ESP_OK, esp_partition_write(chain_partition(),
                                                  second + BLOCK_STORE_RECORD_HEADER_SIZE, &zero, 1));

    reopen();
    TEST_ASSERT_EQUAL(1, s_visited_count);
    TEST_ASSERT_EQUAL(ESP_ERR_NOT_FOUND, block_store_read(second, &s_read_back));
}

TEST_CASE("stare rekordy nie wracaja po sformatowaniu", "[block_store]") {
    fresh_log();
    for (uint32_t height = 1; height <= 5; height++) {
        append(height, BLOCK_MAX_TX);
    }

    TEST_ASSERT_EQUAL(ESP_OK, block_store_format());
    reopen();
    TEST_ASSERT_EQUAL(0, s_visited_count);

    append(100, BLOCK_MAX_TX);
    reopen();
    TEST_ASSERT_EQUAL(1, s_visited_count);
    TEST_ASSERT_EQUAL_UINT32(100, s_visited_heights[0]);
}
