#include "peer_table.h"
#include "node_crypto.h"
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_random.h"

static const char *TAG = "PEER_TABLE";

static known_peer_t s_known_peers[MAX_KNOWN_PEERS];
static int s_known_peers_count = 0;
static bool (*s_is_connected_fn)(const char *) = NULL;

// Sprawdzenie stanu połączenia z danym węzłem
static bool is_peer_connected(const char *ip) {
    if (s_is_connected_fn != NULL && ip != NULL) {
        return s_is_connected_fn(ip);
    }
    return false;
}

// Wyszukanie slotu lub eksmisja węzła LRU
static int find_or_create_peer_slot(const char *ip) {
    if (!ip || ip[0] == '\0') return -1;

    for (int i = 0; i < s_known_peers_count; i++) {
        if (strcmp(s_known_peers[i].ip_address, ip) == 0) {
            return i;
        }
    }

    int slot = -1;
    TickType_t now = xTaskGetTickCount();

    if (s_known_peers_count < MAX_KNOWN_PEERS) {
        slot = s_known_peers_count++;
        ESP_LOGI(TAG, "Dodano nowy wezel do tablicy: %s (slot [%d/%d])", ip, slot + 1, MAX_KNOWN_PEERS);
    } else {
        uint32_t max_age = 0;
        for (int i = 0; i < s_known_peers_count; i++) {
            if (is_peer_connected(s_known_peers[i].ip_address)) {
                continue;
            }
            uint32_t age = (uint32_t)(now - s_known_peers[i].last_seen_ticks);
            if (slot == -1 || age > max_age) {
                max_age = age;
                slot = i;
            }
        }

        if (slot >= 0) {
            ESP_LOGI(TAG, "Tablica pelna (%d/%d). Zastapiono najdawniej widziany wezel %s nowym %s",
                     MAX_KNOWN_PEERS, MAX_KNOWN_PEERS, s_known_peers[slot].ip_address, ip);
        } else {
            ESP_LOGW(TAG, "Brak slotu do zastapienia dla %s (wszystkie wezly aktywnie polaczone)", ip);
            return -1;
        }
    }

    memset(&s_known_peers[slot], 0, sizeof(known_peer_t));
    strncpy(s_known_peers[slot].ip_address, ip, sizeof(s_known_peers[slot].ip_address) - 1);
    s_known_peers[slot].ip_address[sizeof(s_known_peers[slot].ip_address) - 1] = '\0';
    s_known_peers[slot].last_seen_ticks = now;

    return slot;
}

// Inicjalizacja tablicy routingu oraz callbacku połączeń
void peer_table_init(bool (*is_connected_fn)(const char *)) {
    s_known_peers_count = 0;
    s_is_connected_fn = is_connected_fn;
    memset(s_known_peers, 0, sizeof(s_known_peers));
}

// Aktualizacja znacznika aktywności czasowej węzła
void peer_table_touch(const char *ip) {
    if (!ip) return;
    for (int i = 0; i < s_known_peers_count; i++) {
        if (strcmp(s_known_peers[i].ip_address, ip) == 0) {
            s_known_peers[i].last_seen_ticks = xTaskGetTickCount();
            return;
        }
    }
}

// Rejestracja węzła i klucza z plotki
void peer_table_register_discovered_entry(const char *ip, const uint8_t pubkey[33]) {
    if (!ip || ip[0] == '\0') return;

    int slot = find_or_create_peer_slot(ip);
    if (slot < 0) return;

    s_known_peers[slot].last_seen_ticks = xTaskGetTickCount();
    if (!s_known_peers[slot].has_pubkey && pubkey != NULL) {
        memcpy(s_known_peers[slot].public_key, pubkey, 33);
        s_known_peers[slot].has_pubkey = true;
    }
}

// Weryfikacja tożsamości lub przypięcie klucza
bool peer_table_check_or_pin_key(const char *ip, const uint8_t pubkey[33]) {
    if (!ip || !pubkey) return false;

    for (int i = 0; i < s_known_peers_count; i++) {
        if (strcmp(s_known_peers[i].ip_address, ip) == 0) {
            s_known_peers[i].last_seen_ticks = xTaskGetTickCount();
            if (s_known_peers[i].has_pubkey) {
                if (memcmp(s_known_peers[i].public_key, pubkey, 33) != 0) {
                    char expected_hex[19];
                    char received_hex[19];
                    node_crypto_bin_to_hex(s_known_peers[i].public_key, 33, expected_hex, sizeof(expected_hex));
                    node_crypto_bin_to_hex(pubkey, 33, received_hex, sizeof(received_hex));
                    ESP_LOGE(TAG, "[MITM ALERT] Wykryto probe podszycia pod wezel %s!", ip);
                    ESP_LOGE(TAG, "  Oczekiwany Node ID: %s...", expected_hex);
                    ESP_LOGE(TAG, "  Otrzymany Node ID:  %s...", received_hex);
                    return false;
                }
                return true;
            }
            memcpy(s_known_peers[i].public_key, pubkey, 33);
            s_known_peers[i].has_pubkey = true;
            return true;
        }
    }

    int slot = find_or_create_peer_slot(ip);
    if (slot >= 0) {
        memcpy(s_known_peers[slot].public_key, pubkey, 33);
        s_known_peers[slot].has_pubkey = true;
    }
    return true;
}

// Oznaczenie węzła połączonym i reset błędów
void peer_table_mark_connected(const char *ip, const uint8_t pubkey[33]) {
    if (!ip || ip[0] == '\0') return;

    int slot = find_or_create_peer_slot(ip);
    if (slot >= 0) {
        s_known_peers[slot].last_seen_ticks = xTaskGetTickCount();
        s_known_peers[slot].cooldown_until_ticks = 0;
        s_known_peers[slot].failed_attempts = 0;
        if (pubkey != NULL) {
            memcpy(s_known_peers[slot].public_key, pubkey, 33);
            s_known_peers[slot].has_pubkey = true;
        }
    }
}

// Inkrementacja licznika błędów i nałożenie cooldownu
void peer_table_on_connect_failed(const char *ip, uint32_t base_seconds) {
    if (!ip) return;

    for (int i = 0; i < s_known_peers_count; i++) {
        if (strcmp(s_known_peers[i].ip_address, ip) == 0) {
            s_known_peers[i].failed_attempts++;

            if (s_known_peers[i].failed_attempts >= MAX_PEER_FAILED_ATTEMPTS) {
                ESP_LOGW(TAG, "Wezel %s: %d nieudane proby polaczenia z rzedu. Wstrzymano auto-connect.",
                         ip, s_known_peers[i].failed_attempts);
                return;
            }

            uint32_t jitter = esp_random() % 21;
            uint32_t total_sec = (base_seconds > 10 ? base_seconds - 10 : base_seconds) + jitter;
            s_known_peers[i].cooldown_until_ticks = xTaskGetTickCount() + pdMS_TO_TICKS(total_sec * 1000);
            ESP_LOGW(TAG, "Wezel %s nie odpowiedzial (proba %d/%d). Cooldown: %lu s",
                     ip, s_known_peers[i].failed_attempts, MAX_PEER_FAILED_ATTEMPTS, (unsigned long)total_sec);
            return;
        }
    }
}

// Nałożenie czasowego cooldownu z losowym rozrzutem
void peer_table_set_cooldown(const char *ip, uint32_t base_seconds) {
    if (!ip) return;

    for (int i = 0; i < s_known_peers_count; i++) {
        if (strcmp(s_known_peers[i].ip_address, ip) == 0) {
            uint32_t jitter = esp_random() % 21;
            uint32_t total_sec = (base_seconds > 10 ? base_seconds - 10 : base_seconds) + jitter;
            s_known_peers[i].cooldown_until_ticks = xTaskGetTickCount() + pdMS_TO_TICKS(total_sec * 1000);
            ESP_LOGW(TAG, "Wezel %s otrzymal cooldown %lu s (rozlaczenie aktywnej sesji)", ip, (unsigned long)total_sec);
            return;
        }
    }
}

// Usunięcie blokady czasowej dla danego węzła
void peer_table_clear_cooldown(const char *ip) {
    if (!ip) return;

    for (int i = 0; i < s_known_peers_count; i++) {
        if (strcmp(s_known_peers[i].ip_address, ip) == 0) {
            s_known_peers[i].cooldown_until_ticks = 0;
            return;
        }
    }
}

// Losowy wybór kandydata do połączenia wychodzącego
bool peer_table_find_candidate(char *out_ip, size_t max_len) {
    if (!out_ip || max_len == 0) return false;

    int candidates[MAX_KNOWN_PEERS];
    int candidate_count = 0;
    TickType_t now = xTaskGetTickCount();

    for (int i = 0; i < s_known_peers_count; i++) {
        if (is_peer_connected(s_known_peers[i].ip_address)) {
            continue;
        }
        if (s_known_peers[i].failed_attempts >= MAX_PEER_FAILED_ATTEMPTS) {
            continue;
        }
        if (now < s_known_peers[i].cooldown_until_ticks) {
            continue;
        }
        candidates[candidate_count++] = i;
    }

    if (candidate_count == 0) {
        return false;
    }

    int chosen = candidates[esp_random() % candidate_count];
    strncpy(out_ip, s_known_peers[chosen].ip_address, max_len - 1);
    out_ip[max_len - 1] = '\0';
    return true;
}

// Serializacja listy znanych węzłów do bufora
uint32_t peer_table_serialize_addrs(char *out_buf, size_t max_bytes, const char *exclude_ip, uint16_t *out_count) {
    if (!out_buf || max_bytes < sizeof(uint16_t)) {
        if (out_count) *out_count = 0;
        return 0;
    }

    uint16_t count = 0;
    char *ptr = out_buf + sizeof(uint16_t);
    size_t remaining_bytes = max_bytes - sizeof(uint16_t);

    for (int i = 0; i < s_known_peers_count; i++) {
        if (remaining_bytes < sizeof(p2p_addr_entry_t)) break;
        if (exclude_ip != NULL && strcmp(s_known_peers[i].ip_address, exclude_ip) == 0) {
            continue;
        }

        p2p_addr_entry_t entry;
        memset(&entry, 0, sizeof(entry));
        strncpy(entry.ip, s_known_peers[i].ip_address, sizeof(entry.ip) - 1);
        entry.ip[sizeof(entry.ip) - 1] = '\0';
        if (s_known_peers[i].has_pubkey) {
            memcpy(entry.pubkey, s_known_peers[i].public_key, 33);
        }

        memcpy(ptr, &entry, sizeof(entry));
        ptr += sizeof(entry);
        remaining_bytes -= sizeof(entry);
        count++;
    }

    memcpy(out_buf, &count, sizeof(uint16_t));
    if (out_count) *out_count = count;
    return sizeof(uint16_t) + (count * sizeof(p2p_addr_entry_t));
}

// Wyświetlenie zawartości tablicy routingu w CLI
void peer_table_print(void) {
    printf("Tablica Routing (Gossip): %d/%d wezlow\r\n", s_known_peers_count, MAX_KNOWN_PEERS);
    TickType_t now = xTaskGetTickCount();

    for (int i = 0; i < s_known_peers_count; i++) {
        bool connected = is_peer_connected(s_known_peers[i].ip_address);
        char node_id_short[16] = "nieznany";
        if (s_known_peers[i].has_pubkey) {
            node_crypto_bin_to_hex(s_known_peers[i].public_key, 33, node_id_short, 9);
            strcat(node_id_short, "...");
        }

        uint32_t age_sec = 0;
        if (now >= s_known_peers[i].last_seen_ticks) {
            age_sec = ((now - s_known_peers[i].last_seen_ticks) * portTICK_PERIOD_MS) / 1000;
        }

        if (connected) {
            printf("  - %-15s (ID: %s) [POLACZONY]\r\n", s_known_peers[i].ip_address, node_id_short);
        } else if (s_known_peers[i].failed_attempts >= MAX_PEER_FAILED_ATTEMPTS) {
            printf("  - %-15s (ID: %s) [ZABLOKOWANY (3/3 prob) | widziany: %lu s temu]\r\n",
                   s_known_peers[i].ip_address, node_id_short, (unsigned long)age_sec);
        } else if (now < s_known_peers[i].cooldown_until_ticks) {
            uint32_t sec_left = ((s_known_peers[i].cooldown_until_ticks - now) * portTICK_PERIOD_MS) / 1000;
            printf("  - %-15s (ID: %s) [COOLDOWN: %lu s | bledy: %d/%d | widziany: %lu s temu]\r\n", 
                   s_known_peers[i].ip_address, node_id_short, (unsigned long)sec_left,
                   s_known_peers[i].failed_attempts, MAX_PEER_FAILED_ATTEMPTS, (unsigned long)age_sec);
        } else {
            printf("  - %-15s (ID: %s) [GOTOWY | bledy: %d/%d | widziany: %lu s temu]\r\n", 
                   s_known_peers[i].ip_address, node_id_short,
                   s_known_peers[i].failed_attempts, MAX_PEER_FAILED_ATTEMPTS, (unsigned long)age_sec);
        }
    }
}
