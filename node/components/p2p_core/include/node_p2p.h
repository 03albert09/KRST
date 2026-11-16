#ifndef NODE_P2P_H
#define NODE_P2P_H

#include <stdbool.h>
#include <stdint.h>
#include "p2p_protocol.h"

typedef struct {
    int8_t slot;
    uint32_t conn_id;
} p2p_peer_ref_t;

typedef struct {
    void (*on_peer_authenticated)(p2p_peer_ref_t peer);
    bool (*on_message)(p2p_peer_ref_t peer, uint16_t cmd, const uint8_t *payload, uint32_t length);
} node_p2p_handlers_t;

void node_p2p_set_handlers(const node_p2p_handlers_t *handlers);

void node_p2p_disconnect(p2p_peer_ref_t peer);

void node_p2p_init(void);
void node_p2p_start_tasks(void);
void node_p2p_set_wifi_ready(bool is_ready);
void connect_to_peer(const char* target_ip);
void print_node_status(void);
void node_p2p_request_addresses(void);

bool node_p2p_send_to_peer(p2p_peer_ref_t peer, p2p_cmd_t cmd, const void *payload, uint32_t payload_len);

int node_p2p_broadcast(p2p_cmd_t cmd, const void *payload, uint32_t payload_len, const p2p_peer_ref_t *exclude);

#endif
