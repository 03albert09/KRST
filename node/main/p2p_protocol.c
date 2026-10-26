#include "p2p_protocol.h"
#include "node_crypto.h"
#include <string.h>
#include <errno.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "esp_log.h"

static const char *TAG = "P2P_PROTO";

// Pakowanie nagłówka, obliczenie HMAC i wysyłka
bool p2p_send_msg(int sock, p2p_cmd_t cmd, const void *payload, uint32_t payload_len,
                  const uint8_t *session_key, uint32_t seq) {
    if (sock < 0) return false;

    p2p_header_t hdr;
    hdr.magic = MAGIC_BYTES;
    hdr.cmd = (uint16_t)cmd;
    hdr.length = payload_len;
    hdr.seq = seq;

    if (session_key != NULL) {
        node_crypto_calc_msg_hmac(session_key, hdr.magic, hdr.cmd, hdr.length, hdr.seq,
                                  payload, payload_len, hdr.hmac);
    } else {
        memset(hdr.hmac, 0, sizeof(hdr.hmac));
    }

    if (send(sock, &hdr, sizeof(hdr), 0) != sizeof(hdr)) {
        ESP_LOGW(TAG, "Blad wysylania naglowka cmd=%d (errno=%d)", (int)cmd, errno);
        return false;
    }

    if (payload != NULL && payload_len > 0) {
        if (send(sock, payload, payload_len, 0) != (int)payload_len) {
            ESP_LOGW(TAG, "Blad wysylania payloadu cmd=%d (errno=%d)", (int)cmd, errno);
            return false;
        }
    }
    return true;
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
                if (timeouts >= 2) {
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
