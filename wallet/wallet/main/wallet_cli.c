#include "wallet_cli.h"
#include "wallet_types.h"
#include "wallet_vault.h"
#include "wallet_comm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/platform_util.h"

static uint32_t s_failed_attempts = 0;

// Bezpieczny odczyt linii znakow z UART
static void uart_read_line(char *buf, size_t max_len) {
    if (!buf || max_len == 0) return;
    memset(buf, 0, max_len);

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
                buf[idx] = '\0';
                printf("\b \b");
                fflush(stdout);
            }
            continue;
        }
        if (isprint(c) && (idx + 1 < max_len)) {
            buf[idx++] = (char)c;
            putchar(c);
            fflush(stdout);
        }
    }
}

// Konwersja ciagu HEX na bajty binarne
static bool hex_to_bytes(const char *hex, uint8_t *out, size_t expected_bytes) {
    if (!hex || strlen(hex) != expected_bytes * 2) return false;
    for (size_t i = 0; i < expected_bytes; i++) {
        unsigned int val;
        if (sscanf(&hex[i * 2], "%2x", &val) != 1) return false;
        out[i] = (uint8_t)val;
    }
    return true;
}

// Walidacja poprawnosci formatu adresu IPv4
static bool validate_ipv4_str(const char *ip_str) {
    if (!ip_str) return false;
    unsigned int a, b, c, d;
    char tail[2];
    if (sscanf(ip_str, "%u.%u.%u.%u%1s", &a, &b, &c, &d, tail) != 4) {
        return false;
    }
    return (a <= 255 && b <= 255 && c <= 255 && d <= 255);
}

// Blokada czasowa chroniaca przed atakiem bruteforce
static void apply_bruteforce_delay_if_needed(void) {
    if (s_failed_attempts >= 3) {
        uint32_t delay_s = 5 * (s_failed_attempts - 2);
        printf("[ANTI-BRUTEFORCE] Blokada czasowa %lu s...\r\n", (unsigned long)delay_s);
        vTaskDelay(pdMS_TO_TICKS(delay_s * 1000));
    }
}

// Obsluga komendy generowania nowego portfela
static void cmd_generate(char *args) {
    if (!args) {
        printf("[BLAD] Uzycie: generate pass [haslo]\r\n");
        return;
    }
    size_t args_len = strlen(args);

    char *pass_kw = strtok(args, " ");
    char *password = strtok(NULL, "");

    if (!pass_kw || strcmp(pass_kw, "pass") != 0 || !password || strlen(password) == 0) {
        printf("[BLAD] Uzycie: generate pass [haslo]\r\n");
        mbedtls_platform_zeroize(args, args_len);
        return;
    }

    while (*password == ' ') password++;
    if (strlen(password) < 4) {
        printf("[BLAD] Haslo musi miec co najmniej 4 znaki dla bezpieczenstwa.\r\n");
        mbedtls_platform_zeroize(args, args_len);
        return;
    }

    char mnemonic[WALLET_MNEMONIC_MAX_LEN] = {0};
    uint8_t pub[WALLET_PUBKEY_SIZE] = {0};

    esp_err_t err = wallet_vault_generate_wallet(password, mnemonic, pub);

    mbedtls_platform_zeroize(args, args_len);

    if (err == ESP_OK) {
        printf("\r\n=================== [BEZPIECZNA KOPIA ZAPASOWA SEED] ===================\r\n");
        printf(" ZAPISZ PONIZSZE 12 SLOW NA KARTCE PAPIERU I ZACHOWAJ OFFLINE!\r\n");
        printf("------------------------------------------------------------------------\r\n");

        char words_copy[WALLET_MNEMONIC_MAX_LEN] = {0};
        strncpy(words_copy, mnemonic, sizeof(words_copy) - 1);
        words_copy[sizeof(words_copy) - 1] = '\0';
        char *saveptr = NULL;
        char *w = strtok_r(words_copy, " ", &saveptr);
        int idx = 1;
        while (w) {
            printf("  %2d. %-12s", idx, w);
            if (idx % 4 == 0) printf("\r\n");
            idx++;
            w = strtok_r(NULL, " ", &saveptr);
        }
        if ((idx - 1) % 4 != 0) printf("\r\n");
        mbedtls_platform_zeroize(words_copy, sizeof(words_copy));

        printf("------------------------------------------------------------------------\r\n");
        printf(" Pelna fraza (w jednej linii):\r\n");
        printf(" %s\r\n", mnemonic);
        printf("========================================================================\r\n");
        printf("[OK] Nowy portfel zostal pomyslnie utworzony!\r\n");
        printf("[OK] Klucz publiczny (Adres): ");
        for (size_t i = 0; i < WALLET_PUBKEY_SIZE; i++) printf("%02X", pub[i]);
        printf("\r\n");
        printf("[OK] Klucze zaszyfrowane w NVS.\r\n");
        printf("[OK] Klucze prywatne i mnemonik wymazane z pamieci RAM mikrokontrolera.\r\n");
    } else {
        printf("[BLAD] Nie udalo sie wygenerowac i zapisac portfela (kod: 0x%x).\r\n", err);
    }

    mbedtls_platform_zeroize(mnemonic, sizeof(mnemonic));
    mbedtls_platform_zeroize(pub, sizeof(pub));
}

// Obsluga komendy odzyskiwania portfela mnemonikiem
static void cmd_recover(char *args) {
    if (!args) {
        printf("[BLAD] Uzycie: recover pass [haslo] words [12_slow_mnemonika]\r\n");
        return;
    }
    size_t args_len = strlen(args);

    if (strncmp(args, "pass ", 5) != 0) {
        printf("[BLAD] Uzycie: recover pass [haslo] words [12_slow_mnemonika]\r\n");
        mbedtls_platform_zeroize(args, args_len);
        return;
    }

    char *words_ptr = strstr(args + 5, " words ");
    if (!words_ptr) {
        printf("[BLAD] Brak slowa kluczowego 'words'. Uzycie: recover pass [haslo] words [12_slow]\r\n");
        mbedtls_platform_zeroize(args, args_len);
        return;
    }
    *words_ptr = '\0';
    char *password = args + 5;
    char *mnemonic = words_ptr + 7;

    while (*password == ' ') password++;
    while (*mnemonic == ' ') mnemonic++;

    if (strlen(password) < 4) {
        printf("[BLAD] Haslo musi miec co najmniej 4 znaki.\r\n");
        mbedtls_platform_zeroize(args, args_len);
        return;
    }
    if (strlen(mnemonic) == 0) {
        printf("[BLAD] Musisz podac 12 slow mnemotechnicznych.\r\n");
        mbedtls_platform_zeroize(args, args_len);
        return;
    }

    uint8_t pub[WALLET_PUBKEY_SIZE] = {0};
    printf("Weryfikacja 12 slow mnemonika i odzyskiwanie kluczy...\r\n");
    esp_err_t err = wallet_vault_recover_wallet(mnemonic, password, pub);

    mbedtls_platform_zeroize(args, args_len);

    if (err == ESP_OK) {
        printf("[OK] Portfel zostal pomyslnie odzyskany z podanych slow!\r\n");
        printf("[OK] Klucz publiczny (Adres): ");
        for (size_t i = 0; i < WALLET_PUBKEY_SIZE; i++) printf("%02X", pub[i]);
        printf("\r\n");
        printf("[OK] Nowe haslo ustawione, klucze zaszyfrowane w NVS.\r\n");
    } else if (err == ESP_ERR_INVALID_CRC) {
        printf("[BLAD] Blad sumy kontrolnej mnemonika! Sprawdz kolejnosc lub poprawnosc slow.\r\n");
    } else if (err == ESP_ERR_NOT_FOUND) {
        printf("[BLAD] Jedno lub wiecej slow nie istnieje w oficjalnym slowniku BIP-39.\r\n");
    } else if (err == ESP_ERR_INVALID_ARG) {
        printf("[BLAD] Niepoprawna liczba slow (wymagane dokladnie 12 slow).\r\n");
    } else {
        printf("[BLAD] Nie udalo sie odzyskac portfela (kod: 0x%x).\r\n", err);
    }

    mbedtls_platform_zeroize(pub, sizeof(pub));
}

// Obsluga komendy wyswietlenia adresu portfela
static void cmd_address(void) {
    uint8_t address[WALLET_PUBKEY_SIZE];
    if (wallet_vault_get_address(address) != ESP_OK) {
        printf("[BLAD] Brak adresu. Utworz portfel przez 'generate' albo odtworz go przez 'recover'.\r\n");
        return;
    }

    printf("[OK] Adres portfela: ");
    for (size_t i = 0; i < WALLET_PUBKEY_SIZE; i++) printf("%02X", address[i]);
    printf("\r\n");
}

// Obsluga komendy podpisania i wysylki transakcji
static void cmd_transfer(char *args) {
    if (!args) {
        printf("[BLAD] Uzycie: transfer [x] to [y] ip [IP] pass [haslo]\r\n");
        return;
    }
    size_t args_len = strlen(args);

    char *amount_str    = strtok(args, " ");
    char *to_kw         = strtok(NULL, " ");
    char *recipient_hex = strtok(NULL, " ");
    char *next_token    = strtok(NULL, " ");

    if (!amount_str || !to_kw || !recipient_hex || !next_token || strcmp(to_kw, "to") != 0) {
        printf("[BLAD] Uzycie: transfer [x] to [y] ip [IP] pass [haslo]\r\n");
        mbedtls_platform_zeroize(args, args_len);
        return;
    }

    char *ip_str = NULL;
    char *pass_kw = NULL;
    char *password = NULL;

    if (strcmp(next_token, "ip") == 0) {
        ip_str   = strtok(NULL, " ");
        pass_kw  = strtok(NULL, " ");
        password = strtok(NULL, "");
    } else {
        ip_str   = next_token;
        pass_kw  = strtok(NULL, " ");
        password = strtok(NULL, "");
    }

    if (!ip_str || !validate_ipv4_str(ip_str)) {
        printf("[BLAD] Niepoprawny format adresu IP (oczekiwano np. 192.168.1.100).\r\n");
        mbedtls_platform_zeroize(args, args_len);
        return;
    }

    if (!pass_kw || strcmp(pass_kw, "pass") != 0 || !password || strlen(password) == 0) {
        printf("[BLAD] Oczekiwano 'pass [haslo]' na koncu polecenia.\r\n");
        mbedtls_platform_zeroize(args, args_len);
        return;
    }

    while (*password == ' ') password++;

    char *endptr = NULL;
    uint64_t amount = strtoull(amount_str, &endptr, 10);
    if (*endptr != '\0' || amount == 0) {
        printf("[BLAD] Kwota [x] musi byc dodatnia liczba calkowita.\r\n");
        mbedtls_platform_zeroize(args, args_len);
        return;
    }

    uint8_t recipient_pub[WALLET_PUBKEY_SIZE] = {0};
    if (!hex_to_bytes(recipient_hex, recipient_pub, WALLET_PUBKEY_SIZE) ||
        !krst_address_has_valid_prefix(recipient_pub)) {
        printf("[BLAD] Adres odbiorcy [y] musi miec 66 znakow HEX (33 bajty) i zaczynac sie od 02 lub 03.\r\n");
        mbedtls_platform_zeroize(args, args_len);
        return;
    }

    apply_bruteforce_delay_if_needed();

    wallet_transaction_t tx;
    memset(&tx, 0, sizeof(tx));

    printf("Autoryzacja haslem i podpisywanie w locie (Zero-State RAM)...\r\n");
    esp_err_t err = wallet_vault_create_signed_tx(amount, recipient_pub, password, &tx);

    mbedtls_platform_zeroize(args, args_len);

    if (err == ESP_OK) {
        s_failed_attempts = 0;
        printf("[OK] Transakcja podpisana kluczem prywatnym (klucz wymazany z RAM).\r\n");
        wallet_comm_send_tx(&tx, ip_str);
    } else if (err == ESP_ERR_INVALID_CRC) {
        s_failed_attempts++;
        printf("[ODMOWA] Nieprawidlowe haslo lub niezgodne ID procesora!\r\n");
    } else if (err == ESP_ERR_NOT_FOUND) {
        printf("[BLAD] Portfel jest pusty. Uzyj najpierw komendy 'generate pass [haslo]'.\r\n");
    } else {
        printf("[BLAD] Blad kryptograficzny (kod: 0x%x).\r\n", err);
    }

    mbedtls_platform_zeroize(&tx, sizeof(tx));
    mbedtls_platform_zeroize(recipient_pub, sizeof(recipient_pub));
}

// Glowne zadanie petli interpretatora komend CLI
static void wallet_cli_task(void *pvParameters) {
    char line[512];

    printf("\r\n====================================================================\r\n");
    printf("  HARDWARE WALLET\r\n");
    printf("  Komendy:\r\n");
    printf("   1) generate pass [haslo]                      - tworzy klucze i 12 slow kopii zapasowej\r\n");
    printf("   2) recover pass [haslo] words [12 slow]       - odzyskuje portfel z 12 slow mnemonika\r\n");
    printf("   3) transfer [x] to [y] ip [IP] pass [haslo]   - podpisuje i wysyla na adres IP\r\n");
    printf("   4) address                                    - wyswietla adres portfela\r\n");
    printf("====================================================================\r\n");

    while (1) {
        printf("wallet> ");
        fflush(stdout);
        uart_read_line(line, sizeof(line));

        if (strlen(line) > 0) {
            if (strncmp(line, "generate ", 9) == 0) {
                cmd_generate(line + 9);
            } else if (strncmp(line, "init ", 5) == 0) {
                cmd_generate(line + 5);
            } else if (strncmp(line, "recover ", 8) == 0) {
                cmd_recover(line + 8);
            } else if (strncmp(line, "transfer ", 9) == 0) {
                cmd_transfer(line + 9);
            } else if (strcmp(line, "address") == 0) {
                cmd_address();
            } else {
                printf("Nieznana komenda. Dostepne: generate, recover, transfer, address\r\n");
            }
        }

        mbedtls_platform_zeroize(line, sizeof(line));
    }
}

// Uruchomienie watku konsoli CLI portfela
void wallet_cli_start(void) {
    xTaskCreate(wallet_cli_task, "wallet_cli", 8192, NULL, 5, NULL);
}
