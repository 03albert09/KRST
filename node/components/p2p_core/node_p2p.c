#include "node_p2p.h"
#include "p2p_protocol.h"
#include "peer_table.h"
#include "node_crypto.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "lwip/sockets.h"
#include "mbedtls/platform_util.h"

static const char *TAG = "NODE_P2P";

typedef struct {
    uint32_t conn_id;
    char ip_address[16];
    uint8_t peer_pubkey[33];
    bool is_active;
    bool is_inbound;
    TickType_t last_rx_ticks;
    TickType_t last_ping_ticks;
    uint8_t local_challenge[32];
    uint8_t remote_challenge[32];
    uint32_t rx_seq;
} peer_connection_t;

static peer_connection_t active_peers[MAX_ACTIVE_PEERS];

static p2p_channel_t s_channels[MAX_ACTIVE_PEERS];

static SemaphoreHandle_t s_peers_mutex;
static uint32_t s_next_conn_id = 1;

static EventGroupHandle_t s_p2p_event_group;
#define P2P_WIFI_READY_BIT BIT0

#define PEER_RX_STACK_SIZE 6144

static TaskHandle_t s_network_task_handle = NULL;

static node_p2p_handlers_t s_handlers = { 0 };

// Sprawdzenie obecności połączenia z IP (wymaga s_peers_mutex)
static bool is_ip_connected_locked(const char *ip) {
    for (int i = 0; i < MAX_ACTIVE_PEERS; i++) {
        if (active_peers[i].is_active && strcmp(active_peers[i].ip_address, ip) == 0) {
            return true;
        }
    }
    return false;
}

// Zliczanie aktywnych połączeń danego typu (wymaga s_peers_mutex)
static int count_peers_locked(bool inbound) {
    int count = 0;
    for (int i = 0; i < MAX_ACTIVE_PEERS; i++) {
        if (active_peers[i].is_active && active_peers[i].is_inbound == inbound) {
            count++;
        }
    }
    return count;
}

// Sprawdzenie obecności aktywnego połączenia z IP
bool is_ip_already_connected(const char* ip) {
    if (!ip) return false;
    xSemaphoreTake(s_peers_mutex, portMAX_DELAY);
    bool connected = is_ip_connected_locked(ip);
    xSemaphoreGive(s_peers_mutex);
    return connected;
}

// Zliczanie aktywnych połączeń danego typu
static int count_peers(bool inbound) {
    xSemaphoreTake(s_peers_mutex, portMAX_DELAY);
    int count = count_peers_locked(inbound);
    xSemaphoreGive(s_peers_mutex);
    return count;
}

// Alokacja slotu połączenia. Limit przychodzących i duplikat IP są sprawdzane razem z przydziałem.
static int allocate_peer_slot(int sock, const char *ip, bool is_inbound) {
    int slot = -1;
    xSemaphoreTake(s_peers_mutex, portMAX_DELAY);

    bool limit_reached = is_inbound && count_peers_locked(true) >= MAX_INBOUND_PEERS;
    if (!limit_reached && !is_ip_connected_locked(ip)) {
        for (int i = 0; i < MAX_ACTIVE_PEERS; i++) {
            if (!active_peers[i].is_active) {
                slot = i;
                break;
            }
        }
    }

    if (slot >= 0) {
        peer_connection_t *peer = &active_peers[slot];
        memset(peer, 0, sizeof(peer_connection_t));

        uint32_t conn_id = s_next_conn_id++;
        if (conn_id == 0) conn_id = s_next_conn_id++;
        peer->conn_id = conn_id;
        peer->is_inbound = is_inbound;
        strncpy(peer->ip_address, ip, sizeof(peer->ip_address) - 1);
        peer->last_rx_ticks = xTaskGetTickCount();
        peer->last_ping_ticks = peer->last_rx_ticks;
        peer->rx_seq = 1;

        p2p_channel_open(&s_channels[slot], sock, conn_id);
        peer->is_active = true;
    }

    xSemaphoreGive(s_peers_mutex);
    return slot;
}

// Wysłanie ramki przez właściciela slotu (zadanie RX lub kod przed jego startem)
static bool peer_send(int peer_idx, p2p_cmd_t cmd, const void *payload, uint32_t payload_len) {
    if (peer_idx < 0 || peer_idx >= MAX_ACTIVE_PEERS) {
        return false;
    }
    return p2p_channel_send(&s_channels[peer_idx], active_peers[peer_idx].conn_id, cmd, payload, payload_len);
}

// Czyszczenie slotu i nałożenie cooldownu
static void peer_disconnect_cleanup(int peer_idx, const char *peer_ip) {
    p2p_channel_close(&s_channels[peer_idx]);

    xSemaphoreTake(s_peers_mutex, portMAX_DELAY);
    memset(&active_peers[peer_idx], 0, sizeof(peer_connection_t));
    xSemaphoreGive(s_peers_mutex);

    peer_table_set_cooldown(peer_ip, P2P_RECONNECT_COOLDOWN_SEC);
    ESP_LOGI(TAG, "Zwolniono slot [%d] po %s.", peer_idx, peer_ip);

    if (s_network_task_handle != NULL) {
        xTaskNotifyGive(s_network_task_handle);
    }
}

// Finalizacja handshake ECDH oraz aktywacja sesji
static bool finalize_handshake(int peer_idx, const char *peer_ip,
                               const uint8_t chal_a[32], const uint8_t chal_b[32],
                               const uint8_t peer_pubkey[33]) {
    uint8_t shared_secret[32];
    if (!node_crypto_compute_shared_secret(peer_pubkey, shared_secret)) {
        ESP_LOGE(TAG, "Blad obliczania ECDH z %s", peer_ip);
        return false;
    }

    uint8_t session_key[32];
    node_crypto_derive_session_key(shared_secret, chal_a, chal_b, session_key);
    mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));

    active_peers[peer_idx].rx_seq = 1;
    p2p_channel_set_session_key(&s_channels[peer_idx], session_key);
    peer_table_mark_connected(peer_ip, peer_pubkey);

    char node_id_hex[18];
    node_crypto_bin_to_hex(peer_pubkey, 33, node_id_hex, 11);
    char sk_hex[18];
    node_crypto_bin_to_hex(session_key, 32, sk_hex, 11);
    mbedtls_platform_zeroize(session_key, sizeof(session_key));
    ESP_LOGI(TAG, "[AUTH OK] Wzajemna autentykacja z %s (Node ID: %s...) | Sesja: %s...",
             peer_ip, node_id_hex, sk_hex);

    peer_send(peer_idx, CMD_GETADDR, NULL, 0);

    if (s_handlers.on_peer_authenticated != NULL) {
        p2p_peer_ref_t peer = { .slot = (int8_t)peer_idx, .conn_id = active_peers[peer_idx].conn_id };
        s_handlers.on_peer_authenticated(peer);
    }
    return true;
}

// Obsługa powitania CMD_HELLO od klienta
static bool handle_rx_hello(int peer_idx, const char *peer_ip, const void *payload, uint32_t length) {
    if (!payload || length < sizeof(p2p_msg_hello_t)) return false;
    const p2p_msg_hello_t *hello_in = (const p2p_msg_hello_t *)payload;

    if (!peer_table_check_or_pin_key(peer_ip, hello_in->pubkey)) {
        ESP_LOGE(TAG, "[MITM BLOCKED] Polaczenie od %s odrzucone z powodu podmiany klucza!", peer_ip);
        return false;
    }

    memcpy(active_peers[peer_idx].remote_challenge, hello_in->challenge, 32);
    memcpy(active_peers[peer_idx].peer_pubkey, hello_in->pubkey, 33);
    esp_fill_random(active_peers[peer_idx].local_challenge, 32);

    uint8_t my_pubkey[33];
    node_crypto_get_pubkey(my_pubkey);

    uint8_t transcript_hash[32];
    node_crypto_compute_handshake_hash(hello_in->challenge,
                                       active_peers[peer_idx].local_challenge,
                                       hello_in->pubkey,
                                       my_pubkey,
                                       transcript_hash);

    uint8_t sig_b[64];
    if (!node_crypto_sign(transcript_hash, sig_b)) return false;

    p2p_msg_hello_ack_t ack;
    memcpy(ack.challenge, active_peers[peer_idx].local_challenge, 32);
    memcpy(ack.pubkey, my_pubkey, 33);
    memcpy(ack.signature, sig_b, 64);

    if (!peer_send(peer_idx, CMD_HELLO_ACK, &ack, sizeof(ack))) {
        return false;
    }

    ESP_LOGI(TAG, "Odebrano HELLO od %s -> odeslano HELLO_ACK", peer_ip);
    return true;
}

// Weryfikacja odpowiedzi CMD_HELLO_ACK serwera
static bool handle_rx_hello_ack(int peer_idx, const char *peer_ip, const void *payload, uint32_t length) {
    if (!payload || length < sizeof(p2p_msg_hello_ack_t)) return false;
    const p2p_msg_hello_ack_t *ack_in = (const p2p_msg_hello_ack_t *)payload;

    if (!peer_table_check_or_pin_key(peer_ip, ack_in->pubkey)) {
        ESP_LOGE(TAG, "[MITM BLOCKED] Serwer %s przedstawil sfalszowany klucz publiczny!", peer_ip);
        return false;
    }

    memcpy(active_peers[peer_idx].remote_challenge, ack_in->challenge, 32);
    memcpy(active_peers[peer_idx].peer_pubkey, ack_in->pubkey, 33);

    uint8_t my_pubkey[33];
    node_crypto_get_pubkey(my_pubkey);

    uint8_t transcript_hash[32];
    node_crypto_compute_handshake_hash(active_peers[peer_idx].local_challenge,
                                       ack_in->challenge,
                                       my_pubkey,
                                       ack_in->pubkey,
                                       transcript_hash);

    if (!node_crypto_verify(ack_in->pubkey, transcript_hash, ack_in->signature)) {
        ESP_LOGE(TAG, "[MITM BLOCKED] Niepoprawny podpis kryptograficzny serwera %s!", peer_ip);
        return false;
    }

    uint8_t sig_a[64];
    if (!node_crypto_sign(transcript_hash, sig_a)) return false;

    p2p_msg_auth_confirm_t confirm;
    memcpy(confirm.signature, sig_a, 64);
    if (!peer_send(peer_idx, CMD_AUTH_CONFIRM, &confirm, sizeof(confirm))) {
        return false;
    }

    return finalize_handshake(peer_idx, peer_ip,
                              active_peers[peer_idx].local_challenge,
                              active_peers[peer_idx].remote_challenge,
                              ack_in->pubkey);
}

// Weryfikacja potwierdzenia sesji CMD_AUTH_CONFIRM klienta
static bool handle_rx_auth_confirm(int peer_idx, const char *peer_ip, const void *payload, uint32_t length) {
    if (!payload || length < sizeof(p2p_msg_auth_confirm_t)) return false;
    const p2p_msg_auth_confirm_t *conf_in = (const p2p_msg_auth_confirm_t *)payload;

    uint8_t my_pubkey[33];
    node_crypto_get_pubkey(my_pubkey);

    uint8_t transcript_hash[32];
    node_crypto_compute_handshake_hash(active_peers[peer_idx].remote_challenge,
                                       active_peers[peer_idx].local_challenge,
                                       active_peers[peer_idx].peer_pubkey,
                                       my_pubkey,
                                       transcript_hash);

    if (!node_crypto_verify(active_peers[peer_idx].peer_pubkey, transcript_hash, conf_in->signature)) {
        ESP_LOGE(TAG, "[MITM BLOCKED] Niepoprawny podpis kryptograficzny klienta %s!", peer_ip);
        return false;
    }

    return finalize_handshake(peer_idx, peer_ip,
                              active_peers[peer_idx].remote_challenge,
                              active_peers[peer_idx].local_challenge,
                              active_peers[peer_idx].peer_pubkey);
}

// Odesłanie listy znanych adresów GETADDR
static bool handle_rx_getaddr(int peer_idx, const char *peer_ip) {
    if (!s_channels[peer_idx].authenticated) return false;

    char payload[sizeof(uint16_t) + MAX_KNOWN_PEERS * sizeof(p2p_addr_entry_t)];
    uint16_t count = 0;
    uint32_t payload_len = peer_table_serialize_addrs(payload, sizeof(payload), peer_ip, &count);

    if (!peer_send(peer_idx, CMD_ADDR, payload, payload_len)) return false;
    ESP_LOGI(TAG, "Odeslano CMD_ADDR (%u rekordow) do %s", count, peer_ip);
    return true;
}

// Zapis nowych adresów z ramki ADDR
static bool handle_rx_addr(int peer_idx, const char *peer_ip, const void *payload, uint32_t length) {
    if (!payload || length < sizeof(uint16_t)) return false;

    uint16_t count = 0;
    memcpy(&count, payload, sizeof(uint16_t));

    uint32_t expected_min = sizeof(uint16_t) + (count * sizeof(p2p_addr_entry_t));
    if (length < expected_min) {
        ESP_LOGW(TAG, "Niepelny payload CMD_ADDR od %s", peer_ip);
        return false;
    }

    ESP_LOGI(TAG, "Otrzymano zweryfikowane CMD_ADDR od %s (liczba: %u)", peer_ip, count);
    const p2p_addr_entry_t *entries = (const p2p_addr_entry_t *)((const uint8_t *)payload + sizeof(uint16_t));

    for (int i = 0; i < count; i++) {
        char clean_ip[16];
        strncpy(clean_ip, entries[i].ip, 15);
        clean_ip[15] = '\0';

        struct in_addr test_addr;
        if (inet_pton(AF_INET, clean_ip, &test_addr) == 1) {
            if (strcmp(clean_ip, "127.0.0.1") != 0 && strcmp(clean_ip, "0.0.0.0") != 0 && strcmp(clean_ip, peer_ip) != 0) {
                peer_table_register_discovered_entry(clean_ip, entries[i].pubkey);
            }
        }
    }

    if (s_network_task_handle != NULL) {
        xTaskNotifyGive(s_network_task_handle);
    }
    return true;
}

// Pętla odbioru, weryfikacji ramek i pingowania
static void peer_rx_task(void *pvParameters) {
    int peer_idx = (int)(intptr_t)pvParameters;
    int sock = s_channels[peer_idx].sock;
    char peer_ip[16];
    strncpy(peer_ip, active_peers[peer_idx].ip_address, sizeof(peer_ip));
    peer_ip[15] = '\0';

    p2p_socket_set_timeout(sock, P2P_RCV_TIMEOUT_SEC);
    active_peers[peer_idx].last_rx_ticks = xTaskGetTickCount();
    active_peers[peer_idx].last_ping_ticks = xTaskGetTickCount();

    uint8_t *payload_buf = malloc(MAX_PAYLOAD_SIZE);
    if (!payload_buf) {
        ESP_LOGE(TAG, "Brak pamieci RAM na bufor payloadu dla %s", peer_ip);
        peer_disconnect_cleanup(peer_idx, peer_ip);
        vTaskDelete(NULL);
        return;
    }

    while (1) {
        if (p2p_channel_is_broken(&s_channels[peer_idx])) {
            ESP_LOGW(TAG, "Strumien nadawczy do %s jest uszkodzony. Rozlaczanie.", peer_ip);
            break;
        }

        p2p_header_t header;
        p2p_recv_status_t recv_status = p2p_recv_header(sock, &header);
        TickType_t now = xTaskGetTickCount();

        if (recv_status == P2P_RECV_OK) {
            if (header.magic != MAGIC_BYTES) {
                ESP_LOGW(TAG, "Nieprawidlowy naglowek od %s (magic=0x%04X)", peer_ip, header.magic);
                break;
            }

            active_peers[peer_idx].last_rx_ticks = now;
            peer_table_touch(peer_ip);

            if (header.length > MAX_PAYLOAD_SIZE) {
                ESP_LOGE(TAG, "Zbyt duzy payload od %s (%lu B > %d B)",
                         peer_ip, (unsigned long)header.length, MAX_PAYLOAD_SIZE);
                break;
            }

            if (header.length > 0) {
                if (!p2p_recv_exact(sock, payload_buf, header.length)) {
                    ESP_LOGW(TAG, "Blad doczytywania payloadu od %s", peer_ip);
                    break;
                }
            }

            if (s_channels[peer_idx].authenticated) {
                if (header.cmd == CMD_HELLO || header.cmd == CMD_HELLO_ACK || header.cmd == CMD_AUTH_CONFIRM) {
                    ESP_LOGW(TAG, "Odrzucono ponowny handshake od zalogowanego wezla %s", peer_ip);
                    break;
                }

                if (header.seq != active_peers[peer_idx].rx_seq) {
                    ESP_LOGE(TAG, "[MITM / REPLAY DETECTED] Niepoprawny nr sekwencji od %s! Oczekiwano %lu, odebrano %lu",
                             peer_ip, (unsigned long)active_peers[peer_idx].rx_seq, (unsigned long)header.seq);
                    break;
                }

                if (!node_crypto_verify_msg_hmac(s_channels[peer_idx].session_key,
                                                 header.magic, header.cmd, header.length, header.seq,
                                                 header.length > 0 ? payload_buf : NULL, header.length,
                                                 header.hmac)) {
                    ESP_LOGE(TAG, "[MITM TAMPERING DETECTED] Niepoprawny HMAC od %s (cmd=%d)!", peer_ip, header.cmd);
                    break;
                }

                active_peers[peer_idx].rx_seq++;
            } else {
                if (header.cmd != CMD_HELLO && header.cmd != CMD_HELLO_ACK && header.cmd != CMD_AUTH_CONFIRM) {
                    ESP_LOGW(TAG, "Odrzucono cmd=%d od nieuwierzytelnionego wezla %s", header.cmd, peer_ip);
                    break;
                }
            }

            bool ok = true;
            switch (header.cmd) {
                case CMD_HELLO:
                    ok = handle_rx_hello(peer_idx, peer_ip, payload_buf, header.length);
                    break;
                case CMD_HELLO_ACK:
                    ok = handle_rx_hello_ack(peer_idx, peer_ip, payload_buf, header.length);
                    break;
                case CMD_AUTH_CONFIRM:
                    ok = handle_rx_auth_confirm(peer_idx, peer_ip, payload_buf, header.length);
                    break;
                case CMD_GETADDR:
                    ok = handle_rx_getaddr(peer_idx, peer_ip);
                    break;
                case CMD_ADDR:
                    ok = handle_rx_addr(peer_idx, peer_ip, payload_buf, header.length);
                    break;
                case CMD_PING:
                    ok = peer_send(peer_idx, CMD_PONG, NULL, 0);
                    break;
                case CMD_PONG:
                    ok = true;
                    break;
                default:
                    if (s_handlers.on_message != NULL) {
                        p2p_peer_ref_t peer = { .slot = (int8_t)peer_idx, .conn_id = active_peers[peer_idx].conn_id };
                        ok = s_handlers.on_message(peer, header.cmd, payload_buf, header.length);
                    } else {
                        ESP_LOGW(TAG, "Nieznana komenda %d od %s", header.cmd, peer_ip);
                    }
                    break;
            }

            if (!ok) {
                ESP_LOGW(TAG, "Blad przetwarzania komendy %d od %s. Rozlaczanie.", header.cmd, peer_ip);
                break;
            }
        } else if (recv_status == P2P_RECV_CLOSED) {
            ESP_LOGI(TAG, "Wezel %s zamknal polaczenie", peer_ip);
            break;
        } else if (recv_status == P2P_RECV_ERROR) {
            ESP_LOGW(TAG, "Blad odbioru naglowka od %s", peer_ip);
            break;
        }

        if (now - active_peers[peer_idx].last_ping_ticks >= pdMS_TO_TICKS(P2P_PING_INTERVAL_MS)) {
            active_peers[peer_idx].last_ping_ticks = now;
            if (!peer_send(peer_idx, CMD_PING, NULL, 0)) {
                ESP_LOGW(TAG, "Blad wysylania PING do %s", peer_ip);
                break;
            }
        }

        if (now - active_peers[peer_idx].last_rx_ticks >= pdMS_TO_TICKS(P2P_PEER_TIMEOUT_MS)) {
            ESP_LOGW(TAG, "Timeout braku odpowiedzi od %s (15 s bez pakietu). Rozlaczanie.", peer_ip);
            break;
        }
    }

    free(payload_buf);
    peer_disconnect_cleanup(peer_idx, peer_ip);
    vTaskDelete(NULL);
}

// Nawiązanie wychodzącego połączenia TCP z węzłem
void connect_to_peer(const char* target_ip) {
    if (!target_ip || strlen(target_ip) == 0 || is_ip_already_connected(target_ip)) {
        return;
    }

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) return;

    p2p_socket_set_timeout(sock, 3);

    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(P2P_PORT)
    };
    if (inet_pton(AF_INET, target_ip, &dest_addr.sin_addr) <= 0) {
        close(sock);
        return;
    }

    if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == 0) {
        int slot = allocate_peer_slot(sock, target_ip, false);
        if (slot >= 0) {
            esp_fill_random(active_peers[slot].local_challenge, 32);

            p2p_msg_hello_t hello;
            memcpy(hello.challenge, active_peers[slot].local_challenge, 32);
            node_crypto_get_pubkey(hello.pubkey);

            peer_send(slot, CMD_HELLO, &hello, sizeof(hello));
            if (xTaskCreate(peer_rx_task, "peer_rx", PEER_RX_STACK_SIZE, (void*)(intptr_t)slot, 5, NULL) != pdPASS) {
                ESP_LOGE(TAG, "Brak pamieci na zadanie odbiorcze dla %s", target_ip);
                peer_disconnect_cleanup(slot, target_ip);
                return;
            }
            ESP_LOGI(TAG, "Polaczono z %s (slot [%d]), wyslano HELLO z wyzwaniem sesji", target_ip, slot);
        } else {
            ESP_LOGW(TAG, "Brak wolnego slotu albo juz polaczono z %s", target_ip);
            close(sock);
        }
    } else {
        close(sock);
        peer_table_on_connect_failed(target_ip, P2P_RECONNECT_COOLDOWN_SEC);
    }
}

// Serwer nasłuchujący na połączenia TCP
static void p2p_server_task(void *pvParameters) {
    xEventGroupWaitBits(s_p2p_event_group, P2P_WIFI_READY_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (listen_sock < 0) {
        vTaskDelete(NULL);
        return;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(P2P_PORT)
    };

    if (bind(listen_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0 ||
        listen(listen_sock, 4) < 0) {
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Serwer P2P TCP nasluchuje na porcie %d (zabezpieczony ECDH + HMAC)...", P2P_PORT);

    while (1) {
        struct sockaddr_in source_addr;
        socklen_t addr_len = sizeof(source_addr);
        int sock = accept(listen_sock, (struct sockaddr *)&source_addr, &addr_len);
        if (sock < 0) continue;

        char client_ip[16];
        inet_ntoa_r(source_addr.sin_addr, client_ip, sizeof(client_ip));

        int slot = allocate_peer_slot(sock, client_ip, true);
        if (slot >= 0) {
            peer_table_clear_cooldown(client_ip);
            if (xTaskCreate(peer_rx_task, "peer_rx", PEER_RX_STACK_SIZE, (void*)(intptr_t)slot, 5, NULL) != pdPASS) {
                ESP_LOGE(TAG, "Brak pamieci na zadanie odbiorcze dla %s", client_ip);
                peer_disconnect_cleanup(slot, client_ip);
                continue;
            }
            ESP_LOGI(TAG, "Zaakceptowano polaczenie przychodzace od %s (slot [%d], oczekiwanie na handshake)", client_ip, slot);
        } else {
            close(sock);
        }
    }
}

// Dobór kandydata i nawiązanie połączenia wychodzącego
static void try_connect_to_new_peer(void) {
    int max_outbound = MAX_ACTIVE_PEERS - MAX_INBOUND_PEERS;

    while (count_peers(false) < max_outbound) {
        char target_ip[16];
        if (!peer_table_find_candidate(target_ip, sizeof(target_ip))) {
            break;
        }

        ESP_LOGI(TAG, "[P2P Network] Wolny slot. Proba polaczenia z wezlem: %s", target_ip);
        connect_to_peer(target_ip);

        if (!is_ip_already_connected(target_ip)) {
            break;
        }
    }
}

// Cykliczny nadzór nad topologią sieci P2P
static void p2p_network_task(void *pvParameters) {
    s_network_task_handle = xTaskGetCurrentTaskHandle();
    xEventGroupWaitBits(s_p2p_event_group, P2P_WIFI_READY_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    while (1) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(5000));

        EventBits_t bits = xEventGroupGetBits(s_p2p_event_group);
        if (!(bits & P2P_WIFI_READY_BIT)) {
            xEventGroupWaitBits(s_p2p_event_group, P2P_WIFI_READY_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
        }

        try_connect_to_new_peer();
    }
}

// Inicjalizacja struktur P2P, kryptografii i tablicy
void node_p2p_init(void) {
    s_p2p_event_group = xEventGroupCreate();
    s_peers_mutex = xSemaphoreCreateMutex();
    configASSERT(s_peers_mutex != NULL);

    memset(active_peers, 0, sizeof(active_peers));
    for (int i = 0; i < MAX_ACTIVE_PEERS; i++) {
        bool created = p2p_channel_create(&s_channels[i]);
        configASSERT(created);
        (void)created;
    }

    node_crypto_init();
    peer_table_init(is_ip_already_connected);
}

// Uruchomienie zadań serwera TCP i managera
void node_p2p_start_tasks(void) {
    xTaskCreate(p2p_server_task, "p2p_server", 4096, NULL, 5, NULL);
    xTaskCreate(p2p_network_task, "p2p_network", 4096, NULL, 4, NULL);
}

// Aktualizacja stanu gotowości interfejsu WiFi
void node_p2p_set_wifi_ready(bool is_ready) {
    if (is_ready) {
        xEventGroupSetBits(s_p2p_event_group, P2P_WIFI_READY_BIT);
    } else {
        xEventGroupClearBits(s_p2p_event_group, P2P_WIFI_READY_BIT);
    }
}

// Ustawienie obsługi zdarzeń wyższej warstwy
void node_p2p_set_handlers(const node_p2p_handlers_t *handlers) {
    s_handlers = *handlers;
}

// Rozłączenie węzła z dowolnego zadania
void node_p2p_disconnect(p2p_peer_ref_t peer) {
    if (peer.slot >= 0 && peer.slot < MAX_ACTIVE_PEERS) {
        p2p_channel_abort(&s_channels[peer.slot], peer.conn_id);
    }
}

// Wysłanie ramki do uwierzytelnionego węzła z dowolnego zadania
bool node_p2p_send_to_peer(p2p_peer_ref_t peer, p2p_cmd_t cmd, const void *payload, uint32_t payload_len) {
    if (peer.slot < 0 || peer.slot >= MAX_ACTIVE_PEERS || peer.conn_id == 0) {
        return false;
    }

    xSemaphoreTake(s_peers_mutex, portMAX_DELAY);
    bool usable = active_peers[peer.slot].is_active &&
                  active_peers[peer.slot].conn_id == peer.conn_id &&
                  s_channels[peer.slot].authenticated;
    xSemaphoreGive(s_peers_mutex);
    if (!usable) return false;

    return p2p_channel_send(&s_channels[peer.slot], peer.conn_id, cmd, payload, payload_len);
}

// Rozesłanie ramki do uwierzytelnionych węzłów
int node_p2p_broadcast(p2p_cmd_t cmd, const void *payload, uint32_t payload_len, const p2p_peer_ref_t *exclude) {
    p2p_peer_ref_t targets[MAX_ACTIVE_PEERS];
    int target_count = 0;

    xSemaphoreTake(s_peers_mutex, portMAX_DELAY);
    for (int i = 0; i < MAX_ACTIVE_PEERS; i++) {
        if (!active_peers[i].is_active || !s_channels[i].authenticated) continue;
        if (exclude && exclude->slot == i && exclude->conn_id == active_peers[i].conn_id) continue;
        targets[target_count].slot = (int8_t)i;
        targets[target_count].conn_id = active_peers[i].conn_id;
        target_count++;
    }
    xSemaphoreGive(s_peers_mutex);

    int sent = 0;
    for (int i = 0; i < target_count; i++) {
        if (p2p_channel_send(&s_channels[targets[i].slot], targets[i].conn_id, cmd, payload, payload_len)) {
            sent++;
        }
    }
    return sent;
}

// Wysłanie zapytania GETADDR do aktywnych węzłów
void node_p2p_request_addresses(void) {
    int sent = node_p2p_broadcast(CMD_GETADDR, NULL, 0, NULL);
    printf("[P2P] Wyslano zapytanie CMD_GETADDR do %d uwierzytelnionych wezlow.\r\n", sent);
}

// Wyświetlenie statusu połączeń oraz tablicy routingu
void print_node_status(void) {
    printf("\r\n--- STATUS WEZLA P2P ---\r\n");
    uint8_t my_pk[33];
    char my_id[18] = "nieznany";
    if (node_crypto_get_pubkey(my_pk)) {
        node_crypto_bin_to_hex(my_pk, 33, my_id, 11);
        strcat(my_id, "...");
    }
    printf("Lokalny Node ID: %s \r\n", my_id);
    printf("Pamiec RAM: wolne %lu B (minimum w historii: %lu B)\r\n",
           (unsigned long)esp_get_free_heap_size(),
           (unsigned long)esp_get_minimum_free_heap_size());

    int count = 0;
    TickType_t now = xTaskGetTickCount();

    xSemaphoreTake(s_peers_mutex, portMAX_DELAY);
    for (int i = 0; i < MAX_ACTIVE_PEERS; i++) {
        if (active_peers[i].is_active) {
            uint32_t sec_since_rx = ((now - active_peers[i].last_rx_ticks) * portTICK_PERIOD_MS) / 1000;
            char peer_id[18] = "niezweryfikowany";
            char session_id[18] = "brak";
            bool authenticated = s_channels[i].authenticated;
            if (authenticated) {
                node_crypto_bin_to_hex(active_peers[i].peer_pubkey, 33, peer_id, 11);
                strcat(peer_id, "...");
                node_crypto_bin_to_hex(s_channels[i].session_key, 32, session_id, 11);
                strcat(session_id, "...");
            }

            printf("  [%d] %s (Node ID: %s | Sesja: %s) (%s) %s (aktywnosc: %lu s temu)\r\n", 
                i, active_peers[i].ip_address, 
                peer_id, session_id,
                active_peers[i].is_inbound ? "IN" : "OUT",
                authenticated ? "[OK]" : "[WAIT - HANDSHAKE]",
                (unsigned long)sec_since_rx);
            count++;
        }
    }
    xSemaphoreGive(s_peers_mutex);
    if (count == 0) printf("  Brak aktywnych polaczen TCP.\r\n");

    peer_table_print();
    printf("------------------------\r\n");
}
