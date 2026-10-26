#include "node_cli.h"
#include "node_wifi.h"
#include "node_p2p.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/platform_util.h"


//funkcja czytania z konsoli
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

// Składnia: wifi [ssid] [haslo]
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

// Składnia: connect [IP]
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

// Składnia: status
static void cmd_status(void) {
    print_node_status();
}

// Składnia: getaddr
static void cmd_getaddr(void) {
    node_p2p_request_addresses();
}

static void node_cli_task(void *pvParameters) {
    char line[320];

    printf("\r\n====================================================================\r\n");
    printf("  P2P NODE CLI\r\n");
    printf("  Komendy:\r\n");
    printf("   1) wifi [ssid] [haslo]\r\n");
    printf("   2) connect [Adres_IP]\r\n");
    printf("   3) status\r\n");
    printf("   4) getaddr\r\n");
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
        } else {
            printf("Nieznana komenda. Dostepne: wifi, connect, status, getaddr\r\n");
        }

        mbedtls_platform_zeroize(line, sizeof(line));
    }
}

void node_cli_start(void) {
    xTaskCreate(node_cli_task, "node_cli", 3584, NULL, 5, NULL);
}
