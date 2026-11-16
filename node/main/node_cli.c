#include "node_cli.h"
#include "node_wifi.h"
#include "node_p2p.h"
#include "node_crypto.h"
#include "chain.h"
#include "chain_task.h"
#include "consensus.h"
#include "ledger.h"
#include "miner.h"
#include "node_evil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/platform_util.h"
#include "nvs.h"

#define NVS_NAMESPACE  "storage"
#define NVS_KEY_PAYOUT "payout"
#define ADDRESS_HEX_LEN (KRST_PUBKEY_SIZE * 2)
#define BENCH_DURATION_MS 3000

// Odczyt jednej linii z konsoli
static void uart_read_line(char *buf, size_t max_len) {
    size_t idx = 0;
    while (1) {
        int c = fgetc(stdin);
        if (c == EOF) {
            vTaskDelay(pdMS_TO_TICKS(15));
            continue;
        }
        if (c == '\r' || c == '\n') {
            printf("\r\n");
            fflush(stdout);
            buf[idx] = '\0';
            return;
        }
        if (c == 0x08 || c == 0x7F) {
            if (idx > 0) {
                idx--;
                printf("\b \b");
                fflush(stdout);
            }
            continue;
        }
        if (idx < max_len - 1 && isprint(c)) {
            buf[idx++] = (char)c;
            fputc(c, stdout);
            fflush(stdout);
        }
    }
}

// Komenda wifi: połączenie z siecią WiFi o podanym SSID i haśle
static void cmd_wifi(char *args) {
    char *ssid = strtok(args, " ");
    char *pass = strtok(NULL, " ");

    if (!ssid || !pass) {
        printf("[BLAD] Uzycie: wifi [ssid] [haslo]\r\n");
        return;
    }

    printf("[OK] Laczenie z siecia WiFi: %s...\r\n", ssid);
    connect_wifi(ssid, pass);
}

// Komenda connect: połączenie z węzłem o podanym adresie IP
static void cmd_connect(char *args) {
    char *ip_str = strtok(args, " ");

    if (!ip_str) {
        printf("[BLAD] Uzycie: connect [Adres_IP]\r\n");
        printf("       np.:    connect 192.168.1.50\r\n");
        return;
    }

    if (strlen(ip_str) > 15) {
        printf("[BLAD] Niepoprawny format adresu IP.\r\n");
        return;
    }

    printf("[OK] Rozpoczeto probe polaczenia z wezlem: %s\r\n", ip_str);
    connect_to_peer(ip_str);
}

// Komenda status: stan połączeń, łańcucha, górnika i zegara
static void cmd_status(void) {
    print_node_status();

    chain_tip_t tip;
    char tip_hex[17];
    chain_get_tip(&tip);
    node_crypto_bin_to_hex(tip.hash, 8, tip_hex, sizeof(tip_hex));
    printf("Lancuch: wysokosc %lu, tip %s..., znanych blokow %u\r\n",
           (unsigned long)tip.height, tip_hex, (unsigned)tip.block_count);
    printf("Gornik: %s\r\n", miner_is_running() ? "pracuje" : "zatrzymany");

    if (node_time_is_synced()) {
        time_t now = time(NULL);
        struct tm utc;
        char time_str[24];
        gmtime_r(&now, &utc);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &utc);
        printf("Zegar: %s UTC (SNTP)\r\n", time_str);
    } else {
        printf("Zegar: brak synchronizacji SNTP\r\n");
    }
}

// Komenda getaddr: zapytanie sąsiadów o znane adresy
static void cmd_getaddr(void) {
    node_p2p_request_addresses();
}

// Odczyt adresu portfela z tekstu HEX (małe lub wielkie litery)
static bool parse_address(const char *hex, uint8_t out_address[KRST_PUBKEY_SIZE]) {
    if (strlen(hex) != ADDRESS_HEX_LEN) {
        return false;
    }
    for (size_t i = 0; i < ADDRESS_HEX_LEN; i++) {
        if (!isxdigit((unsigned char)hex[i])) {
            return false;
        }
    }
    for (size_t i = 0; i < KRST_PUBKEY_SIZE; i++) {
        unsigned int value = 0;
        sscanf(&hex[i * 2], "%2x", &value);
        out_address[i] = (uint8_t)value;
    }
    return node_crypto_is_valid_pubkey(out_address);
}

// Wypisanie adresu w formacie HEX
static void print_address(const uint8_t address[KRST_PUBKEY_SIZE]) {
    for (size_t i = 0; i < KRST_PUBKEY_SIZE; i++) {
        printf("%02X", address[i]);
    }
}

// Odczyt adresu nagród z NVS
static bool load_payout(uint8_t out_address[KRST_PUBKEY_SIZE]) {
    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) {
        return false;
    }

    size_t size = KRST_PUBKEY_SIZE;
    esp_err_t err = nvs_get_blob(nvs, NVS_KEY_PAYOUT, out_address, &size);
    nvs_close(nvs);
    return err == ESP_OK && size == KRST_PUBKEY_SIZE;
}

// Zapis adresu nagród w NVS
static bool save_payout(const uint8_t address[KRST_PUBKEY_SIZE]) {
    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs) != ESP_OK) {
        return false;
    }

    esp_err_t err = nvs_set_blob(nvs, NVS_KEY_PAYOUT, address, KRST_PUBKEY_SIZE);
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
    }
    nvs_close(nvs);
    return err == ESP_OK;
}

// Komenda payout: wyświetlenie albo ustawienie adresu nagród
static void cmd_payout(char *args) {
    uint8_t address[KRST_PUBKEY_SIZE];
    char *hex = strtok(args, " ");

    if (hex == NULL) {
        if (load_payout(address)) {
            printf("Adres nagrod: ");
            print_address(address);
            printf("\r\n");
        } else {
            printf("Adres nagrod nie jest ustawiony. Uzycie: payout [adres_portfela]\r\n");
        }
        return;
    }

    if (!parse_address(hex, address)) {
        printf("[BLAD] Adres musi miec %d znakow HEX i byc poprawnym kluczem secp256k1.\r\n", ADDRESS_HEX_LEN);
        return;
    }
    if (miner_is_running()) {
        printf("[BLAD] Najpierw zatrzymaj gornika: mine stop\r\n");
        return;
    }
    if (!save_payout(address)) {
        printf("[BLAD] Nie udalo sie zapisac adresu.\r\n");
        return;
    }
    printf("[OK] Nagrody beda trafiac na adres portfela.\r\n");
}

// Komenda balance: saldo podanego adresu albo adresu nagród
static void cmd_balance(char *args) {
    uint8_t address[KRST_PUBKEY_SIZE];
    char *hex = strtok(args, " ");

    if (hex != NULL) {
        if (!parse_address(hex, address)) {
            printf("[BLAD] Adres musi miec %d znakow HEX i byc poprawnym kluczem secp256k1.\r\n", ADDRESS_HEX_LEN);
            return;
        }
    } else if (!load_payout(address)) {
        printf("[BLAD] Podaj adres albo ustaw go komenda payout. Uzycie: balance [adres]\r\n");
        return;
    }

    printf("Saldo: %" PRIu64 "\r\n", ledger_get_balance(address));
}

// Skasowanie łańcucha w zadaniu łańcucha, jedynym, które wolno mu zmieniać
static void work_chain_reset(void *arg, p2p_peer_ref_t source) {
    (void)arg;
    (void)source;
    esp_err_t err = chain_reset();
    printf("%s\r\n", err == ESP_OK ? "[OK] Lancuch skasowany." : "[BLAD] Nie udalo sie skasowac lancucha.");
}

// Komenda chain reset: skasowanie łańcucha przez zadanie łańcucha
static void cmd_chain(char *args) {
    char *action = strtok(args, " ");

    if (action == NULL || strcmp(action, "reset") != 0) {
        printf("[BLAD] Uzycie: chain reset\r\n");
        return;
    }
    if (miner_is_running()) {
        printf("[BLAD] Najpierw zatrzymaj gornika: mine stop\r\n");
        return;
    }
    if (!chain_task_post_work(work_chain_reset, NULL, CHAIN_SOURCE_LOCAL, pdMS_TO_TICKS(1000))) {
        printf("[BLAD] Kolejka lancucha jest pelna.\r\n");
    }
}

// Komenda mine: uruchomienie, zatrzymanie albo pomiar szybkości kopania
static void cmd_mine(char *args) {
    char *action = strtok(args, " ");

    if (action != NULL && strcmp(action, "start") == 0) {
        uint8_t payout[KRST_PUBKEY_SIZE];
        if (!load_payout(payout)) {
            printf("[BLAD] Najpierw ustaw adres portfela: payout [adres]\r\n");
            return;
        }
        if (miner_start(payout) != ESP_OK) {
            printf("[BLAD] Gornik juz pracuje albo brak pamieci.\r\n");
            return;
        }
        printf("[OK] Kopanie uruchomione.\r\n");
    } else if (action != NULL && strcmp(action, "stop") == 0) {
        miner_stop();
        printf("[OK] Zatrzymywanie gornika.\r\n");
    } else if (action != NULL && strcmp(action, "bench") == 0) {
        if (miner_is_running()) {
            printf("[BLAD] Najpierw zatrzymaj gornika: mine stop\r\n");
            return;
        }

        printf("Pomiar trwa %d s...\r\n", BENCH_DURATION_MS / 1000);
        uint32_t hashrate = miner_measure_hashrate(BENCH_DURATION_MS);

        chain_tip_t tip;
        chain_get_tip(&tip);
        uint32_t target = chain_next_target(&tip);
        uint64_t hashes_per_block = consensus_block_work(target);

        printf("Szybkosc: %" PRIu32 " H/s\r\n", hashrate);
        printf("Prog: 0x%08" PRIX32 ", srednio %" PRIu64 " hashy na blok, czyli okolo %" PRIu64 " s\r\n",
               target, hashes_per_block, hashrate > 0 ? hashes_per_block / hashrate : 0);
    } else {
        printf("[BLAD] Uzycie: mine start|stop|bench\r\n");
    }
}

// Pętla CLI węzła: odczyt komend i wywołanie ich obsługi
static void node_cli_task(void *pvParameters) {
    char line[320];

    printf("\r\n====================================================================\r\n");
    printf("  P2P NODE CLI\r\n");
    printf("  Komendy:\r\n");
    printf("   1) wifi [ssid] [haslo]\r\n");
    printf("   2) connect [Adres_IP]\r\n");
    printf("   3) status\r\n");
    printf("   4) getaddr\r\n");
    printf("   5) payout [adres_portfela]\r\n");
    printf("   6) balance [adres_portfela]\r\n");
    printf("   7) mine start|stop|bench\r\n");
    printf("   8) chain reset\r\n");
    printf("   9) evil [wada] (zlosliwy wezel)\r\n");
    printf("====================================================================\r\n");

    while (1) {
        printf("node> ");
        fflush(stdout);
        uart_read_line(line, sizeof(line));

        if (strlen(line) == 0) continue;

        if (strncmp(line, "wifi ", 5) == 0) {
            cmd_wifi(line + 5);
        } else if (strncmp(line, "connect ", 8) == 0) {
            cmd_connect(line + 8);
        } else if (strncmp(line, "status", 6) == 0) {
            cmd_status();
        } else if (strncmp(line, "getaddr", 7) == 0) {
            cmd_getaddr();
        } else if (strncmp(line, "payout", 6) == 0) {
            cmd_payout(line + 6);
        } else if (strncmp(line, "balance", 7) == 0) {
            cmd_balance(line + 7);
        } else if (strncmp(line, "mine", 4) == 0) {
            cmd_mine(line + 4);
        } else if (strncmp(line, "chain", 5) == 0) {
            cmd_chain(line + 5);
        } else if (strncmp(line, "evil", 4) == 0) {
            node_evil_command(line + 4);
        } else {
            printf("Nieznana komenda. Dostepne: wifi, connect, status, getaddr, payout, balance, mine, chain, evil\r\n");
        }

        mbedtls_platform_zeroize(line, sizeof(line));
    }
}

// Uruchomienie zadania CLI węzła
void node_cli_start(void) {
    xTaskCreate(node_cli_task, "node_cli", 6144, NULL, 5, NULL);
}
