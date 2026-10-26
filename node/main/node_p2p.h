#ifndef NODE_P2P_H
#define NODE_P2P_H

#include <stdbool.h>

void node_p2p_init(void);
void node_p2p_start_tasks(void);
void node_p2p_set_wifi_ready(bool is_ready);
void connect_to_peer(const char* target_ip);
void print_node_status(void);
void node_p2p_request_addresses(void);

#endif // NODE_P2P_H
