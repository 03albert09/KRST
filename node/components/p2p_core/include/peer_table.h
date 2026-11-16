#ifndef PEER_TABLE_H
#define PEER_TABLE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "freertos/FreeRTOS.h"
#include "p2p_protocol.h"

#define MAX_PEER_FAILED_ATTEMPTS 3

typedef struct {
    char ip_address[16];
    uint8_t public_key[33];
    bool has_pubkey;
    TickType_t last_seen_ticks;
    TickType_t cooldown_until_ticks;
    uint8_t failed_attempts;
} known_peer_t;

void peer_table_init(bool (*is_connected_fn)(const char *));
void peer_table_register_discovered_entry(const char *ip, const uint8_t pubkey[33]);
bool peer_table_check_or_pin_key(const char *ip, const uint8_t pubkey[33]);
void peer_table_mark_connected(const char *ip, const uint8_t pubkey[33]);
void peer_table_touch(const char *ip);
void peer_table_on_connect_failed(const char *ip, uint32_t base_seconds);
void peer_table_set_cooldown(const char *ip, uint32_t base_seconds);
void peer_table_clear_cooldown(const char *ip);
bool peer_table_find_candidate(char *out_ip, size_t max_len);
uint32_t peer_table_serialize_addrs(char *out_buf, size_t max_bytes, const char *exclude_ip, uint16_t *out_count);
void peer_table_print(void);

#endif
