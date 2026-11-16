#ifndef P2P_PROTOCOL_H
#define P2P_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#define P2P_PORT                   8333
#define MAGIC_BYTES                0xF1B9

#define MAX_ACTIVE_PEERS           4
#define MAX_INBOUND_PEERS          2
#define MAX_KNOWN_PEERS            20

#define P2P_PING_INTERVAL_MS       5000
#define P2P_PEER_TIMEOUT_MS        15000
#define P2P_RCV_TIMEOUT_SEC        2
#define P2P_RECONNECT_COOLDOWN_SEC 60
#define MAX_PAYLOAD_SIZE           1500

typedef enum {
    CMD_HELLO = 1,
    CMD_HELLO_ACK,
    CMD_AUTH_CONFIRM,
    CMD_GETADDR,
    CMD_ADDR,
    CMD_NEW_BLOCK,
    CMD_TX,
    CMD_PING,
    CMD_PONG,
    CMD_CHAIN_STATUS = 10,
    CMD_GET_BLOCKS = 11,
    CMD_BLOCK = 12,
    CMD_BLOCKS_END = 13,
    CMD_GET_STATUS = 14
} p2p_cmd_t;

typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint16_t cmd;
    uint32_t length;
    uint32_t seq;
    uint8_t  hmac[16];
} p2p_header_t;

typedef struct __attribute__((packed)) {
    uint8_t challenge[32];
    uint8_t pubkey[33];
} p2p_msg_hello_t;

typedef struct __attribute__((packed)) {
    uint8_t challenge[32];
    uint8_t pubkey[33];
    uint8_t signature[64];
} p2p_msg_hello_ack_t;

typedef struct __attribute__((packed)) {
    uint8_t signature[64];
} p2p_msg_auth_confirm_t;

typedef struct __attribute__((packed)) {
    char ip[16];
    uint8_t pubkey[33];
} p2p_addr_entry_t;

typedef struct {
    SemaphoreHandle_t lock;
    int sock;
    uint32_t conn_id;
    bool authenticated;
    bool broken;
    uint32_t tx_seq;
    uint8_t session_key[32];
} p2p_channel_t;

bool p2p_channel_create(p2p_channel_t *ch);

void p2p_channel_open(p2p_channel_t *ch, int sock, uint32_t conn_id);

void p2p_channel_set_session_key(p2p_channel_t *ch, const uint8_t session_key[32]);

bool p2p_channel_send(p2p_channel_t *ch, uint32_t conn_id, p2p_cmd_t cmd,
                      const void *payload, uint32_t payload_len);

bool p2p_channel_is_broken(p2p_channel_t *ch);

void p2p_channel_abort(p2p_channel_t *ch, uint32_t conn_id);

void p2p_channel_close(p2p_channel_t *ch);

typedef enum {
    P2P_RECV_OK,
    P2P_RECV_IDLE,
    P2P_RECV_CLOSED,
    P2P_RECV_ERROR
} p2p_recv_status_t;

p2p_recv_status_t p2p_recv_header(int sock, p2p_header_t *out_header);

bool p2p_recv_exact(int sock, void *buf, size_t total_len);
void p2p_socket_set_timeout(int sock, int sec);

#endif
