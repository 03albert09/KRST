#ifndef NODE_WIFI_H
#define NODE_WIFI_H

#include <stdbool.h>

void node_wifi_init(void);
void connect_wifi(const char* ssid, const char* pass);

bool node_time_is_synced(void);

#endif
