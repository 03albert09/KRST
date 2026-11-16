#include <string.h>
#include "unity.h"
#include "block.h"
#include "block_vectors.h"
#include "p2p_protocol.h"

#define BLOCK_BASE_SIZE 82

static block_t s_block;
static block_t s_parsed;

// Te same wartosci buduje sample_tx() w gen_block_vectors.py
static void sample_tx(krst_tx_t *tx, uint8_t i) {
    memset(tx, 0, sizeof(*tx));
    tx->type = KRST_TX_TRANSFER;
    tx->nonce = i;
    tx->sender[0] = 0x02;
    memset(tx->sender + 1, i, 32);
    tx->recipient[0] = 0x03;
    memset(tx->recipient + 1, i + 1, 32);
    tx->amount = 1000 + i;
    memset(tx->signature, i, sizeof(tx->signature));
}

// Buduje blok z przykladowymi transakcjami i poprawnym korzeniem Merkle
static void make_valid_block(block_t *block, uint16_t tx_count) {
    memset(block, 0, sizeof(*block));
    block->tx_count = tx_count;
    for (uint16_t i = 0; i < tx_count; i++) {
        sample_tx(&block->txs[i], (uint8_t)(i + 1));
    }
    TEST_ASSERT_TRUE(block_merkle_root(block->txs, tx_count, block->header.merkle_root));
}

TEST_CASE("uklad transakcji w pamieci zgadza sie z wektorem", "[tx]") {
    krst_tx_t tx;
    sample_tx(&tx, 1);
    TEST_ASSERT_EQUAL(sizeof(BV_TX_BYTES), sizeof(tx));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(BV_TX_BYTES, &tx, sizeof(tx));
}

TEST_CASE("skrot do podpisu zgadza sie z wektorem i pomija podpis", "[tx]") {
    krst_tx_t tx;
    uint8_t hash[KRST_HASH_SIZE];
    sample_tx(&tx, 1);

    krst_tx_signing_hash(&tx, hash);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(BV_TX_SIGNING_HASH, hash, sizeof(hash));

    tx.signature[0] ^= 0xFF;
    krst_tx_signing_hash(&tx, hash);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(BV_TX_SIGNING_HASH, hash, sizeof(hash));

    tx.amount++;
    krst_tx_signing_hash(&tx, hash);
    TEST_ASSERT_FALSE(memcmp(BV_TX_SIGNING_HASH, hash, sizeof(hash)) == 0);
}

TEST_CASE("adres musi miec prefiks klucza skompresowanego", "[tx]") {
    uint8_t address[KRST_PUBKEY_SIZE] = {0};
    TEST_ASSERT_FALSE(krst_address_has_valid_prefix(address));
    address[0] = 0x02;
    TEST_ASSERT_TRUE(krst_address_has_valid_prefix(address));
    address[0] = 0x03;
    TEST_ASSERT_TRUE(krst_address_has_valid_prefix(address));
    address[0] = 0x04;
    TEST_ASSERT_FALSE(krst_address_has_valid_prefix(address));
}

TEST_CASE("skrot naglowka zgadza sie z wektorem", "[block]") {
    block_header_t header;
    uint8_t hash[KRST_HASH_SIZE];

    TEST_ASSERT_EQUAL(sizeof(BV_HEADER_BYTES), sizeof(header));
    memcpy(&header, BV_HEADER_BYTES, sizeof(header));
    TEST_ASSERT_EQUAL_UINT32(7, header.height);
    TEST_ASSERT_EQUAL_UINT32(123456, header.nonce);

    block_header_hash(&header, hash);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(BV_HEADER_HASH, hash, sizeof(hash));

    header.nonce++;
    block_header_hash(&header, hash);
    TEST_ASSERT_FALSE(memcmp(BV_HEADER_HASH, hash, sizeof(hash)) == 0);
}

TEST_CASE("korzen Merkle zgadza sie z wektorami dla roznych liczb transakcji", "[block]") {
    static krst_tx_t txs[BLOCK_MAX_TX];
    for (int i = 0; i < BLOCK_MAX_TX; i++) {
        sample_tx(&txs[i], (uint8_t)(i + 1));
    }

    uint8_t root[KRST_HASH_SIZE];
    TEST_ASSERT_TRUE(block_merkle_root(txs, 1, root));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(BV_MERKLE_1, root, sizeof(root));
    TEST_ASSERT_TRUE(block_merkle_root(txs, 2, root));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(BV_MERKLE_2, root, sizeof(root));
    TEST_ASSERT_TRUE(block_merkle_root(txs, 3, root));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(BV_MERKLE_3, root, sizeof(root));
    TEST_ASSERT_TRUE(block_merkle_root(txs, 9, root));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(BV_MERKLE_9, root, sizeof(root));
}

TEST_CASE("korzen Merkle odrzuca niepoprawna liczbe transakcji", "[block]") {
    static krst_tx_t txs[BLOCK_MAX_TX];
    uint8_t root[KRST_HASH_SIZE];
    TEST_ASSERT_FALSE(block_merkle_root(txs, 0, root));
    TEST_ASSERT_FALSE(block_merkle_root(txs, BLOCK_MAX_TX + 1, root));
}

TEST_CASE("korzen Merkle zalezy od kolejnosci i wykrywa dopisana kopie transakcji", "[block]") {
    static krst_tx_t txs[4];
    uint8_t original[KRST_HASH_SIZE];
    uint8_t changed[KRST_HASH_SIZE];

    sample_tx(&txs[0], 1);
    sample_tx(&txs[1], 2);
    sample_tx(&txs[2], 3);
    TEST_ASSERT_TRUE(block_merkle_root(txs, 3, original));

    memcpy(&txs[3], &txs[2], sizeof(krst_tx_t));
    TEST_ASSERT_TRUE(block_merkle_root(txs, 4, changed));
    TEST_ASSERT_FALSE(memcmp(original, changed, sizeof(original)) == 0);

    sample_tx(&txs[0], 2);
    sample_tx(&txs[1], 1);
    TEST_ASSERT_TRUE(block_merkle_root(txs, 3, changed));
    TEST_ASSERT_FALSE(memcmp(original, changed, sizeof(original)) == 0);
}

TEST_CASE("blok przechodzi przez parser bez zmian", "[block]") {
    make_valid_block(&s_block, 2);
    size_t size = block_serialized_size(&s_block);
    TEST_ASSERT_EQUAL(BLOCK_BASE_SIZE + 2 * sizeof(krst_tx_t), size);

    memset(&s_parsed, 0xEE, sizeof(s_parsed));
    TEST_ASSERT_EQUAL(BLOCK_OK, block_parse((const uint8_t *)&s_block, size, &s_parsed));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(&s_block, &s_parsed, size);
    TEST_ASSERT_EQUAL(BLOCK_OK, block_check_structure(&s_parsed));
}

TEST_CASE("najwiekszy blok miesci sie w ramce i przechodzi przez parser", "[block]") {
    make_valid_block(&s_block, BLOCK_MAX_TX);
    size_t size = block_serialized_size(&s_block);
    TEST_ASSERT_LESS_OR_EQUAL(MAX_PAYLOAD_SIZE, size);
    TEST_ASSERT_EQUAL(BLOCK_OK, block_parse((const uint8_t *)&s_block, size, &s_parsed));
}

TEST_CASE("parser odrzuca bledne dlugosci", "[block]") {
    make_valid_block(&s_block, 2);
    const uint8_t *data = (const uint8_t *)&s_block;
    size_t size = block_serialized_size(&s_block);

    TEST_ASSERT_EQUAL(BLOCK_ERR_TRUNCATED, block_parse(NULL, size, &s_parsed));
    TEST_ASSERT_EQUAL(BLOCK_ERR_TRUNCATED, block_parse(data, 0, &s_parsed));
    TEST_ASSERT_EQUAL(BLOCK_ERR_TRUNCATED, block_parse(data, BLOCK_BASE_SIZE - 1, &s_parsed));
    TEST_ASSERT_EQUAL(BLOCK_ERR_SIZE, block_parse(data, size - 1, &s_parsed));
    TEST_ASSERT_EQUAL(BLOCK_ERR_SIZE, block_parse(data, size + 1, &s_parsed));

    s_block.tx_count = BLOCK_MAX_TX + 1;
    TEST_ASSERT_EQUAL(BLOCK_ERR_TOO_MANY_TX, block_parse(data, size, &s_parsed));
    s_block.tx_count = 0xFFFF;
    TEST_ASSERT_EQUAL(BLOCK_ERR_TOO_MANY_TX, block_parse(data, size, &s_parsed));
    s_block.tx_count = 1;
    TEST_ASSERT_EQUAL(BLOCK_ERR_SIZE, block_parse(data, size, &s_parsed));
}

TEST_CASE("kontrola struktury wykrywa brak transakcji, ich nadmiar i podmiane", "[block]") {
    make_valid_block(&s_block, 2);
    TEST_ASSERT_EQUAL(BLOCK_OK, block_check_structure(&s_block));

    make_valid_block(&s_block, 2);
    s_block.tx_count = 0;
    TEST_ASSERT_EQUAL(BLOCK_ERR_NO_TX, block_check_structure(&s_block));

    make_valid_block(&s_block, 2);
    s_block.tx_count = BLOCK_MAX_TX + 1;
    TEST_ASSERT_EQUAL(BLOCK_ERR_TOO_MANY_TX, block_check_structure(&s_block));

    make_valid_block(&s_block, 2);
    s_block.txs[1].amount++;
    TEST_ASSERT_EQUAL(BLOCK_ERR_MERKLE, block_check_structure(&s_block));

    make_valid_block(&s_block, 2);
    s_block.txs[1].signature[0] ^= 0x01;
    TEST_ASSERT_EQUAL(BLOCK_ERR_MERKLE, block_check_structure(&s_block));

    make_valid_block(&s_block, 2);
    s_block.tx_count = 1;
    TEST_ASSERT_EQUAL(BLOCK_ERR_MERKLE, block_check_structure(&s_block));
}
