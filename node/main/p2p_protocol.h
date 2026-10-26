#ifndef P2P_PROTOCOL_H
#define P2P_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// =========================================================================
// STALE PROTOKOLU P2P
// =========================================================================
#define P2P_PORT                   8333
#define MAGIC_BYTES                0xF1B9

#define MAX_ACTIVE_PEERS           4     
#define MAX_INBOUND_PEERS          2     
#define MAX_KNOWN_PEERS            20      

#define P2P_PING_INTERVAL_MS       5000   // Wysylanie PING co 5 sekund
#define P2P_PEER_TIMEOUT_MS        15000  // Limit braku odpowiedzi (15 sekund = 3 pominiete pingi)
#define P2P_RCV_TIMEOUT_SEC        2      // Timeout gniazda na operacje recv() w sekundach
#define P2P_RECONNECT_COOLDOWN_SEC 60     // Baza cooldownu (60 s) dla wezla, ktory przestal odpowiadac
#define MAX_PAYLOAD_SIZE           1500   // Maksymalny dopuszczalny rozmiar pojedynczego payloadu

// =========================================================================
// KOMENDY PROTOKOLU
// =========================================================================
typedef enum {
    CMD_HELLO = 1,       
    CMD_HELLO_ACK,        
    CMD_AUTH_CONFIRM,   
    CMD_GETADDR,
    CMD_ADDR,
    CMD_NEW_BLOCK,
    CMD_TX,
    CMD_PING,
    CMD_PONG
} p2p_cmd_t;

// =========================================================================
// NAGLOWEK RAMKI P2P (ZABEZPIECZONY HMAC I ANTY-REPLAY)
// =========================================================================
typedef struct __attribute__((packed)) {
    uint16_t magic;       // 0xF1B9 (2 bajty)
    uint16_t cmd;         // p2p_cmd_t (2 bajty)
    uint32_t length;      // Dlugosc payloadu (4 bajty)
    uint32_t seq;         // Numer sekwencyjny w sesji (4 bajty, ochrona przed powtorzeniem)
    uint8_t  hmac[16];    // 16 bajtow HMAC-SHA256 (weryfikacja integralnosci i klucza sesji)
} p2p_header_t;

// =========================================================================
// STRUKTURY PAKIETOW HANDSHAKE (MITM PROTECTION)
// =========================================================================
typedef struct __attribute__((packed)) {
    uint8_t challenge[32];
    uint8_t pubkey[33];
} p2p_msg_hello_t; // 65 bajtow

typedef struct __attribute__((packed)) {
    uint8_t challenge[32];
    uint8_t pubkey[33];
    uint8_t signature[64];
} p2p_msg_hello_ack_t; // 129 bajtow

typedef struct __attribute__((packed)) {
    uint8_t signature[64];
} p2p_msg_auth_confirm_t; // 64 bajty

typedef struct __attribute__((packed)) {
    char ip[16];
    uint8_t pubkey[33];
} p2p_addr_entry_t; // 49 bajtow


bool p2p_send_msg(int sock, p2p_cmd_t cmd, const void *payload, uint32_t payload_len,
                  const uint8_t *session_key, uint32_t seq);
bool p2p_recv_exact(int sock, void *buf, size_t total_len);
void p2p_socket_set_timeout(int sock, int sec);

#endif // P2P_PROTOCOL_H
