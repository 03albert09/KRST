#include "chain_net.h"
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "chain_task.h"

static const char *TAG = "CHAIN_NET";

#define CHAIN_NET_QUEUE_WAIT_MS 1000
#define CHAIN_NET_SYNC_TIMEOUT_MS 15000
#define CHAIN_NET_WORK_UNKNOWN UINT64_MAX

_Static_assert(sizeof(block_t) <= MAX_PAYLOAD_SIZE, "Blok musi miescic sie w jednej ramce");
_Static_assert(sizeof(chain_net_get_blocks_t) <= MAX_PAYLOAD_SIZE, "Lokator musi miescic sie w jednej ramce");

typedef struct {
    bool active;                // trwa sync
    p2p_peer_ref_t peer;        // z kim
    TickType_t requested_at;    // kiedy GET_BLOCKS (timeout)
    uint32_t height_at_request; // czy paczka coś dała
    uint32_t height_at_start;   // czy sync coś dał
    bool has_next;              // czeka lepszy peer
    p2p_peer_ref_t next_peer;   // kto czeka
    uint64_t next_work;         // jego praca
} sync_state_t;

static chain_net_transport_t s_transport;
static sync_state_t s_sync;

static uint32_t s_skip_batch[MAX_ACTIVE_PEERS];

// Porównanie odwołań do połączeń
static bool same_peer(p2p_peer_ref_t a, p2p_peer_ref_t b) {
    return a.slot == b.slot && a.conn_id == b.conn_id;
}

// Sprawdzenie, czy reszta partii od tego połączenia jest pomijana
static bool skipping_batch(p2p_peer_ref_t peer) {
    return peer.slot >= 0 && peer.slot < MAX_ACTIVE_PEERS && peer.conn_id != 0 &&
           s_skip_batch[peer.slot] == peer.conn_id;
}

// Włączenie albo wyłączenie pomijania reszty partii
static void set_skipping_batch(p2p_peer_ref_t peer, bool skip) {
    if (peer.slot >= 0 && peer.slot < MAX_ACTIVE_PEERS) {
        s_skip_batch[peer.slot] = skip ? peer.conn_id : 0;
    }
}

// Zbudowanie wiadomości o stanie łańcucha
static void build_status(chain_net_status_t *status) {
    chain_tip_t tip;
    chain_get_tip(&tip);

    chain_get_network_id(status->network_id);
    memcpy(status->tip_hash, tip.hash, KRST_HASH_SIZE);
    status->cumulative_work = tip.cumulative_work;
    status->height = tip.height;
}

// Wysłanie prośby o kolejne bloki
static void request_blocks(p2p_peer_ref_t peer) {
    chain_net_get_blocks_t request;
    request.count = chain_build_locator(request.hashes, CHAIN_NET_MAX_LOCATOR);
    uint32_t length = offsetof(chain_net_get_blocks_t, hashes) + (uint32_t)request.count * KRST_HASH_SIZE;

    chain_tip_t tip;
    chain_get_tip(&tip);
    s_sync.height_at_request = tip.height;
    s_sync.requested_at = xTaskGetTickCount();

    if (!s_transport.send(peer, CMD_GET_BLOCKS, &request, length)) {
        s_sync.active = false;
    }
}

// Rozpoczęcie synchronizacji. Gdy jedna już trwa, sąsiad z największą pracą czeka na swoją kolej.
static void start_sync(p2p_peer_ref_t peer, uint64_t peer_work) {
    TickType_t now = xTaskGetTickCount();
    if (s_sync.active && now - s_sync.requested_at < pdMS_TO_TICKS(CHAIN_NET_SYNC_TIMEOUT_MS)) {
        if (!s_sync.has_next || peer_work > s_sync.next_work) {
            s_sync.has_next = true;
            s_sync.next_peer = peer;
            s_sync.next_work = peer_work;
        }
        return;
    }

    chain_tip_t tip;
    chain_get_tip(&tip);

    s_sync.active = true;
    s_sync.peer = peer;
    s_sync.height_at_start = tip.height;
    ESP_LOGI(TAG, "Synchronizacja od wysokosci %lu", (unsigned long)tip.height);
    request_blocks(peer);
}

// Zakończenie synchronizacji
static void finish_sync(void) {
    s_sync.active = false;

    chain_tip_t tip;
    chain_get_tip(&tip);
    ESP_LOGI(TAG, "Koniec synchronizacji na wysokosci %lu", (unsigned long)tip.height);

    if (tip.height != s_sync.height_at_start) {
        chain_net_status_t status;
        build_status(&status);
        s_transport.broadcast(CMD_CHAIN_STATUS, &status, sizeof(status), NULL);
    }

    if (s_sync.has_next) {
        s_sync.has_next = false;
        if (s_sync.next_work > tip.cumulative_work) {
            start_sync(s_sync.next_peer, s_sync.next_work);
        }
    }
}

// Reakcja na stan łańcucha drugiego węzła
static void work_handle_status(void *arg, p2p_peer_ref_t source) {
    chain_net_status_t *status = (chain_net_status_t *)arg;

    chain_tip_t tip;
    chain_get_tip(&tip);
    if (status->cumulative_work > tip.cumulative_work) {
        start_sync(source, status->cumulative_work);
    }
    free(status);
}

// Odpowiedź na prośbę o bloki
static void work_handle_get_blocks(void *arg, p2p_peer_ref_t source) {
    chain_net_get_blocks_t *request = (chain_net_get_blocks_t *)arg;
    chain_net_blocks_end_t end = { .more = 0 };

    uint32_t common = 0;
    block_t *block = malloc(sizeof(block_t));
    if (block != NULL && chain_find_common_height(request->hashes, request->count, &common)) {
        chain_tip_t tip;
        chain_get_tip(&tip);

        uint32_t height = common + 1;
        uint32_t last = common + CHAIN_NET_BATCH_SIZE;
        if (last > tip.height) {
            last = tip.height;
        }

        while (height <= last) {
            if (!chain_read_main_block(height, block) ||
                !s_transport.send(source, CMD_BLOCK, block, (uint32_t)block_serialized_size(block))) {
                break;
            }
            height++;
        }
        end.more = height <= tip.height ? 1 : 0;
    }

    s_transport.send(source, CMD_BLOCKS_END, &end, sizeof(end));
    free(block);
    free(request);
}

// Reakcja na koniec partii bloków
static void work_handle_blocks_end(void *arg, p2p_peer_ref_t source) {
    chain_net_blocks_end_t *end = (chain_net_blocks_end_t *)arg;
    bool more = end->more != 0;
    free(end);

    if (!s_sync.active || !same_peer(s_sync.peer, source)) {
        return;
    }

    chain_tip_t tip;
    chain_get_tip(&tip);

    if (more && tip.height > s_sync.height_at_request) {
        request_blocks(source);
    } else {
        finish_sync();
    }
}

// Przekazanie kopii wiadomości do zadania łańcucha
static void post_copy(chain_task_work_fn work, const uint8_t *payload, uint32_t length, p2p_peer_ref_t peer) {
    void *copy = malloc(length);
    if (copy == NULL) {
        ESP_LOGW(TAG, "Brak pamieci na wiadomosc");
        return;
    }

    memcpy(copy, payload, length);
    if (!chain_task_post_work(work, copy, peer, pdMS_TO_TICKS(CHAIN_NET_QUEUE_WAIT_MS))) {
        ESP_LOGW(TAG, "Kolejka lancucha pelna. Wiadomosc porzucona.");
        free(copy);
    }
}

// Porzucenie bloku i pominięcie reszty partii, bo kolejne bloki nie miałyby rodzica. BLOCKS_END wznowi pobieranie od luki.
static void drop_block(p2p_peer_ref_t peer, bool relay) {
    if (!relay && !skipping_batch(peer)) {
        set_skipping_batch(peer, true);
        ESP_LOGW(TAG, "Pomijanie reszty partii do CMD_BLOCKS_END");
    }
}

// Odbiór bloku: nowego albo z synchronizacji
static bool handle_block(p2p_peer_ref_t peer, const uint8_t *payload, uint32_t length, bool relay) {
    block_t *block = malloc(sizeof(block_t));
    if (block == NULL) {
        ESP_LOGW(TAG, "Brak pamieci na blok");
        drop_block(peer, relay);
        return true;
    }

    block_result_t parsed = block_parse(payload, length, block);
    if (parsed != BLOCK_OK) {
        ESP_LOGW(TAG, "Niepoprawny format bloku: %s", block_result_str(parsed));
        free(block);
        return false;
    }

    if (!relay && skipping_batch(peer)) {
        free(block);
        return true;
    }

    if (!chain_task_submit_block(block, peer, relay, pdMS_TO_TICKS(CHAIN_NET_QUEUE_WAIT_MS))) {
        ESP_LOGW(TAG, "Kolejka lancucha pelna. Blok porzucony.");
        free(block);
        drop_block(peer, relay);
    }
    return true;
}

// Odbiór stanu łańcucha
static bool handle_status(p2p_peer_ref_t peer, const uint8_t *payload, uint32_t length) {
    if (length != sizeof(chain_net_status_t)) {
        ESP_LOGW(TAG, "Niepoprawna dlugosc CMD_CHAIN_STATUS: %lu", (unsigned long)length);
        return false;
    }

    uint8_t network_id[KRST_HASH_SIZE];
    chain_get_network_id(network_id);
    if (memcmp(((const chain_net_status_t *)payload)->network_id, network_id, KRST_HASH_SIZE) != 0) {
        ESP_LOGW(TAG, "Wezel nalezy do innej sieci (inny genesis albo trudnosc)");
        return false;
    }

    post_copy(work_handle_status, payload, length, peer);
    return true;
}

// Odbiór prośby o bloki
static bool handle_get_blocks(p2p_peer_ref_t peer, const uint8_t *payload, uint32_t length) {
    const uint32_t base = offsetof(chain_net_get_blocks_t, hashes);
    if (length < base) {
        ESP_LOGW(TAG, "Zbyt krotkie CMD_GET_BLOCKS");
        return false;
    }

    uint16_t count;
    memcpy(&count, payload, sizeof(count));
    if (count == 0 || count > CHAIN_NET_MAX_LOCATOR || length != base + (uint32_t)count * KRST_HASH_SIZE) {
        ESP_LOGW(TAG, "Niepoprawny lokator w CMD_GET_BLOCKS (liczba hashy: %u)", (unsigned)count);
        return false;
    }

    post_copy(work_handle_get_blocks, payload, length, peer);
    return true;
}

// Inicjalizacja warstwy sieciowej łańcucha
void chain_net_init(const chain_net_transport_t *transport) {
    s_transport = *transport;
    memset(&s_sync, 0, sizeof(s_sync));
    memset(s_skip_batch, 0, sizeof(s_skip_batch));
}

// Wysłanie stanu łańcucha jednemu węzłowi
static void send_status(p2p_peer_ref_t peer) {
    chain_net_status_t status;
    build_status(&status);
    s_transport.send(peer, CMD_CHAIN_STATUS, &status, sizeof(status));
}

// Wysłanie stanu łańcucha po uwierzytelnieniu węzła
void chain_net_on_peer_authenticated(p2p_peer_ref_t peer) {
    send_status(peer);
}

// Okresowe sprawdzenie, czy synchronizacja nie utknęła
void chain_net_tick(TickType_t now) {
    if (!s_sync.active || now - s_sync.requested_at < pdMS_TO_TICKS(CHAIN_NET_SYNC_TIMEOUT_MS)) {
        return;
    }

    ESP_LOGW(TAG, "Synchronizacja utknela. Pytanie sasiadow o stan lancucha.");
    s_sync.active = false;
    s_sync.has_next = false;
    s_transport.broadcast(CMD_GET_STATUS, NULL, 0, NULL);
}

// Obsługa wiadomości od węzła
bool chain_net_handle_message(p2p_peer_ref_t peer, uint16_t cmd, const uint8_t *payload, uint32_t length) {
    switch (cmd) {
        case CMD_NEW_BLOCK:
            return handle_block(peer, payload, length, true);
        case CMD_BLOCK:
            return handle_block(peer, payload, length, false);
        case CMD_CHAIN_STATUS:
            return handle_status(peer, payload, length);
        case CMD_GET_BLOCKS:
            return handle_get_blocks(peer, payload, length);
        case CMD_GET_STATUS:
            if (length != 0) {
                ESP_LOGW(TAG, "Niepoprawna dlugosc CMD_GET_STATUS: %lu", (unsigned long)length);
                return false;
            }
            send_status(peer);
            return true;
        case CMD_BLOCKS_END:
            if (length != sizeof(chain_net_blocks_end_t)) {
                ESP_LOGW(TAG, "Niepoprawna dlugosc CMD_BLOCKS_END: %lu", (unsigned long)length);
                return false;
            }
            set_skipping_batch(peer, false);
            post_copy(work_handle_blocks_end, payload, length, peer);
            return true;
        default:
            ESP_LOGW(TAG, "Nieobslugiwana komenda %u", (unsigned)cmd);
            return true;
    }
}

// Reakcja na wynik przetworzenia bloku
void chain_net_on_block_result(const block_t *block, chain_result_t result, block_result_t reason,
                               p2p_peer_ref_t source, bool relay) {
    (void)reason;
    bool from_peer = source.slot >= 0;

    switch (result) {
        case CHAIN_ACCEPTED_TIP:
            if (relay) {
                s_transport.broadcast(CMD_NEW_BLOCK, block, (uint32_t)block_serialized_size(block), &source);
            }
            break;
        case CHAIN_ORPHAN:
            if (from_peer) {
                start_sync(source, CHAIN_NET_WORK_UNKNOWN);
            }
            break;
        case CHAIN_INVALID:
            if (from_peer) {
                ESP_LOGW(TAG, "Rozlaczanie wezla, ktory wyslal niepoprawny blok");
                s_transport.disconnect(source);
            }
            break;
        default:
            break;
    }
}
