#include "p2p_protocol.h"
#include "node_crypto.h"
#include <string.h>
#include <errno.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "esp_log.h"
#include "mbedtls/platform_util.h"

static const char *TAG = "P2P_PROTO";

#define P2P_MAX_IO_TIMEOUTS 2

// Wysyłka całego bufora z obsługą częściowego send()
static bool send_all(int sock, const void *buf, size_t total_len) {
    const uint8_t *ptr = (const uint8_t *)buf;
    size_t sent = 0;
    int timeouts = 0;

    while (sent < total_len) {
        int r = send(sock, ptr + sent, total_len - sent, 0);
        if (r > 0) {
            sent += r;
            timeouts = 0;
            continue;
        }

        int err = errno;
        if (r == 0 || err == EAGAIN || err == EWOULDBLOCK) {
            timeouts++;
            if (timeouts >= P2P_MAX_IO_TIMEOUTS) {
                ESP_LOGW(TAG, "Timeout podczas wysylania (%d/%d bajtow)", (int)sent, (int)total_len);
                return false;
            }
            continue;
        }
        ESP_LOGW(TAG, "Blad gniazda podczas wysylania (errno=%d)", err);
        return false;
    }
    return true;
}

// Utworzenie blokady kanału
bool p2p_channel_create(p2p_channel_t *ch) {
    memset(ch, 0, sizeof(*ch));
    ch->sock = -1;
    ch->lock = xSemaphoreCreateMutex();
    return ch->lock != NULL;
}

// Podpięcie nowego połączenia pod kanał
void p2p_channel_open(p2p_channel_t *ch, int sock, uint32_t conn_id) {
    xSemaphoreTake(ch->lock, portMAX_DELAY);
    ch->sock = sock;
    ch->conn_id = conn_id;
    ch->authenticated = false;
    ch->broken = false;
    ch->tx_seq = 0;
    mbedtls_platform_zeroize(ch->session_key, sizeof(ch->session_key));
    xSemaphoreGive(ch->lock);
}

// Aktywacja podpisywania ramek kluczem sesji
void p2p_channel_set_session_key(p2p_channel_t *ch, const uint8_t session_key[32]) {
    xSemaphoreTake(ch->lock, portMAX_DELAY);
    memcpy(ch->session_key, session_key, sizeof(ch->session_key));
    ch->tx_seq = 1;
    ch->authenticated = true;
    xSemaphoreGive(ch->lock);
}

// Pakowanie nagłówka, obliczenie HMAC i wysyłka całej ramki pod blokadą
bool p2p_channel_send(p2p_channel_t *ch, uint32_t conn_id, p2p_cmd_t cmd,
                      const void *payload, uint32_t payload_len) {
    if (!ch || conn_id == 0) return false;

    xSemaphoreTake(ch->lock, portMAX_DELAY);

    if (ch->conn_id != conn_id || ch->sock < 0 || ch->broken) {
        xSemaphoreGive(ch->lock);
        return false;
    }

    p2p_header_t hdr;
    hdr.magic = MAGIC_BYTES;
    hdr.cmd = (uint16_t)cmd;
    hdr.length = payload_len;
    hdr.seq = ch->authenticated ? ch->tx_seq : 0;

    if (ch->authenticated) {
        node_crypto_calc_msg_hmac(ch->session_key, hdr.magic, hdr.cmd, hdr.length, hdr.seq,
                                  payload, payload_len, hdr.hmac);
    } else {
        memset(hdr.hmac, 0, sizeof(hdr.hmac));
    }

    bool ok = send_all(ch->sock, &hdr, sizeof(hdr));
    if (ok && payload != NULL && payload_len > 0) {
        ok = send_all(ch->sock, payload, payload_len);
    }

    if (ok) {
        if (ch->authenticated) ch->tx_seq++;
    } else {
        ESP_LOGW(TAG, "Nieudana wysylka cmd=%d (polaczenie %lu). Zamykanie strumienia.",
                 (int)cmd, (unsigned long)conn_id);
        ch->broken = true;
        shutdown(ch->sock, SHUT_RDWR);
    }

    xSemaphoreGive(ch->lock);
    return ok;
}

// Sprawdzenie, czy strumień nadawczy jest uszkodzony
bool p2p_channel_is_broken(p2p_channel_t *ch) {
    xSemaphoreTake(ch->lock, portMAX_DELAY);
    bool broken = ch->broken;
    xSemaphoreGive(ch->lock);
    return broken;
}

// Zerwanie połączenia na żądanie
void p2p_channel_abort(p2p_channel_t *ch, uint32_t conn_id) {
    xSemaphoreTake(ch->lock, portMAX_DELAY);
    if (conn_id != 0 && ch->conn_id == conn_id && ch->sock >= 0) {
        ch->broken = true;
        shutdown(ch->sock, SHUT_RDWR);
    }
    xSemaphoreGive(ch->lock);
}

// Zamknięcie gniazda i skasowanie klucza sesji
void p2p_channel_close(p2p_channel_t *ch) {
    xSemaphoreTake(ch->lock, portMAX_DELAY);
    if (ch->sock >= 0) {
        close(ch->sock);
    }
    ch->sock = -1;
    ch->conn_id = 0;
    ch->authenticated = false;
    ch->broken = false;
    ch->tx_seq = 0;
    mbedtls_platform_zeroize(ch->session_key, sizeof(ch->session_key));
    xSemaphoreGive(ch->lock);
}

// Odbiór nagłówka, także gdy TCP dostarczy go w kawałkach
p2p_recv_status_t p2p_recv_header(int sock, p2p_header_t *out_header) {
    int len = recv(sock, out_header, sizeof(p2p_header_t), 0);

    if (len == 0) {
        return P2P_RECV_CLOSED;
    }
    if (len < 0) {
        int err = errno;
        if (err == EAGAIN || err == EWOULDBLOCK) {
            return P2P_RECV_IDLE;
        }
        ESP_LOGW(TAG, "Blad gniazda podczas odbioru naglowka (errno=%d)", err);
        return P2P_RECV_ERROR;
    }

    if ((size_t)len < sizeof(p2p_header_t)) {
        uint8_t *rest = (uint8_t *)out_header + len;
        if (!p2p_recv_exact(sock, rest, sizeof(p2p_header_t) - (size_t)len)) {
            return P2P_RECV_ERROR;
        }
    }
    return P2P_RECV_OK;
}

// Odbiór dokładnej liczby bajtów z gniazda
bool p2p_recv_exact(int sock, void *buf, size_t total_len) {
    size_t received = 0;
    uint8_t *ptr = (uint8_t *)buf;
    int timeouts = 0;

    while (received < total_len) {
        int r = recv(sock, ptr + received, total_len - received, 0);
        if (r > 0) {
            received += r;
            timeouts = 0;
        } else if (r == 0) {
            ESP_LOGW(TAG, "Polaczenie zamkniete przez wezel w trakcie odbioru danych");
            return false;
        } else {
            int err = errno;
            if (err == EAGAIN || err == EWOULDBLOCK) {
                timeouts++;
                if (timeouts >= P2P_MAX_IO_TIMEOUTS) {
                    ESP_LOGW(TAG, "Timeout podczas odbioru danych (%d/%d bajtow)",
                             (int)received, (int)total_len);
                    return false;
                }
                continue;
            }
            ESP_LOGW(TAG, "Blad gniazda podczas odbioru (errno=%d)", err);
            return false;
        }
    }
    return true;
}

// Konfiguracja limitu czasu operacji na gnieździe
void p2p_socket_set_timeout(int sock, int sec) {
    struct timeval tv = {
        .tv_sec = sec,
        .tv_usec = 0
    };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}
