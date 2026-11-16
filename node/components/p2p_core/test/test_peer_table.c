#include <stdio.h>
#include <string.h>
#include "unity.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "peer_table.h"

static const char *s_connected_ip = NULL;

// Zastepcza kontrola polaczenia: polaczony jest tylko wybrany adres
static bool fake_is_connected(const char *ip) {
    return s_connected_ip != NULL && strcmp(ip, s_connected_ip) == 0;
}

// Czysci tablice routingu
static void reset_table(void) {
    s_connected_ip = NULL;
    peer_table_init(fake_is_connected);
}

// Klucz publiczny z poprawnym prefiksem wypelniony podanym bajtem
static void make_key(uint8_t key[33], uint8_t fill) {
    memset(key, fill, 33);
    key[0] = 0x02;
}

// Sprawdza, czy adres jest w tablicy, na podstawie serializacji
static bool table_contains(const char *ip) {
    static char buf[sizeof(uint16_t) + MAX_KNOWN_PEERS * sizeof(p2p_addr_entry_t)];
    uint16_t count = 0;
    peer_table_serialize_addrs(buf, sizeof(buf), NULL, &count);

    const p2p_addr_entry_t *entries = (const p2p_addr_entry_t *)(buf + sizeof(uint16_t));
    for (uint16_t i = 0; i < count; i++) {
        if (strcmp(entries[i].ip, ip) == 0) return true;
    }
    return false;
}

TEST_CASE("TOFU przypina klucz i odrzuca podmiane", "[peer_table]") {
    reset_table();
    uint8_t key_a[33], key_b[33];
    make_key(key_a, 0xAA);
    make_key(key_b, 0xBB);

    TEST_ASSERT_TRUE(peer_table_check_or_pin_key("10.0.0.1", key_a));
    TEST_ASSERT_TRUE(peer_table_check_or_pin_key("10.0.0.1", key_a));
    TEST_ASSERT_FALSE(peer_table_check_or_pin_key("10.0.0.1", key_b));

    TEST_ASSERT_TRUE(peer_table_check_or_pin_key("10.0.0.1", key_a));
}

TEST_CASE("klucz poznany z gossipu jest wymuszany przy polaczeniu", "[peer_table]") {
    reset_table();
    uint8_t key_a[33], key_b[33];
    make_key(key_a, 0xAA);
    make_key(key_b, 0xBB);

    peer_table_register_discovered_entry("10.0.0.2", key_a);
    TEST_ASSERT_FALSE(peer_table_check_or_pin_key("10.0.0.2", key_b));
    TEST_ASSERT_TRUE(peer_table_check_or_pin_key("10.0.0.2", key_a));

    peer_table_register_discovered_entry("10.0.0.2", key_b);
    TEST_ASSERT_TRUE(peer_table_check_or_pin_key("10.0.0.2", key_a));
}

TEST_CASE("wezel na cooldownie nie jest kandydatem", "[peer_table]") {
    reset_table();
    uint8_t key[33];
    make_key(key, 0xAA);
    peer_table_register_discovered_entry("10.0.0.3", key);

    char ip[16];
    TEST_ASSERT_TRUE(peer_table_find_candidate(ip, sizeof(ip)));
    TEST_ASSERT_EQUAL_STRING("10.0.0.3", ip);

    peer_table_set_cooldown("10.0.0.3", 60);
    TEST_ASSERT_FALSE(peer_table_find_candidate(ip, sizeof(ip)));

    peer_table_clear_cooldown("10.0.0.3");
    TEST_ASSERT_TRUE(peer_table_find_candidate(ip, sizeof(ip)));
}

TEST_CASE("po trzech nieudanych probach wezel jest wstrzymany az do polaczenia", "[peer_table]") {
    reset_table();
    uint8_t key[33];
    make_key(key, 0xAA);
    peer_table_register_discovered_entry("10.0.0.4", key);

    for (int i = 0; i < MAX_PEER_FAILED_ATTEMPTS; i++) {
        peer_table_on_connect_failed("10.0.0.4", 60);
    }
    peer_table_clear_cooldown("10.0.0.4");

    char ip[16];
    TEST_ASSERT_FALSE(peer_table_find_candidate(ip, sizeof(ip)));

    peer_table_mark_connected("10.0.0.4", key);
    TEST_ASSERT_TRUE(peer_table_find_candidate(ip, sizeof(ip)));
}

TEST_CASE("polaczony wezel nie jest kandydatem", "[peer_table]") {
    reset_table();
    uint8_t key[33];
    make_key(key, 0xAA);
    peer_table_register_discovered_entry("10.0.0.5", key);
    s_connected_ip = "10.0.0.5";

    char ip[16];
    TEST_ASSERT_FALSE(peer_table_find_candidate(ip, sizeof(ip)));
}

TEST_CASE("serializacja pomija wskazany adres i pilnuje rozmiaru bufora", "[peer_table]") {
    reset_table();
    uint8_t key[33];
    make_key(key, 0xAA);
    peer_table_register_discovered_entry("10.0.0.6", key);
    peer_table_register_discovered_entry("10.0.0.7", key);

    char buf[sizeof(uint16_t) + 2 * sizeof(p2p_addr_entry_t)];
    uint16_t count = 0;

    uint32_t written = peer_table_serialize_addrs(buf, sizeof(buf), "10.0.0.6", &count);
    TEST_ASSERT_EQUAL_UINT16(1, count);
    TEST_ASSERT_EQUAL_UINT32(sizeof(uint16_t) + sizeof(p2p_addr_entry_t), written);
    const p2p_addr_entry_t *entries = (const p2p_addr_entry_t *)(buf + sizeof(uint16_t));
    TEST_ASSERT_EQUAL_STRING("10.0.0.7", entries[0].ip);

    written = peer_table_serialize_addrs(buf, sizeof(uint16_t) + sizeof(p2p_addr_entry_t), NULL, &count);
    TEST_ASSERT_EQUAL_UINT16(1, count);
    TEST_ASSERT_EQUAL_UINT32(sizeof(uint16_t) + sizeof(p2p_addr_entry_t), written);
}

TEST_CASE("pelna tablica usuwa najdawniej widziany niepolaczony wezel", "[peer_table]") {
    reset_table();
    uint8_t key[33];
    make_key(key, 0xAA);

    char ip[16];
    for (int i = 0; i < MAX_KNOWN_PEERS; i++) {
        snprintf(ip, sizeof(ip), "10.0.1.%d", i + 1);
        peer_table_register_discovered_entry(ip, key);
        vTaskDelay(1);
    }

    s_connected_ip = "10.0.1.1";
    peer_table_register_discovered_entry("10.0.2.1", key);

    TEST_ASSERT_TRUE(table_contains("10.0.2.1"));
    TEST_ASSERT_TRUE(table_contains("10.0.1.1"));
    TEST_ASSERT_FALSE(table_contains("10.0.1.2"));
    TEST_ASSERT_TRUE(table_contains("10.0.1.3"));
}
