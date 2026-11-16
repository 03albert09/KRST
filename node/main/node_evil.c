#include "node_evil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "chain.h"
#include "evil_block.h"
#include "miner.h"
#include "node_p2p.h"

#define EVIL_TASK_STACK    4096
#define EVIL_TASK_PRIORITY 1

typedef struct {
    const char *name;       // nazwa w CLI
    evil_block_kind_t kind; // rodzaj złego bloku
    const char *expected;   // oczekiwana reakcja peera
} evil_option_t;

static const evil_option_t EVIL_OPTIONS[] = {
    { "pow",    EVIL_BLOCK_POW,       "BLOCK_ERR_POW, rozlaczenie" },
    { "merkle", EVIL_BLOCK_MERKLE,    "BLOCK_ERR_MERKLE, rozlaczenie" },
    { "target", EVIL_BLOCK_TARGET,    "BLOCK_ERR_TARGET, rozlaczenie" },
    { "height", EVIL_BLOCK_HEIGHT,    "BLOCK_ERR_HEIGHT, rozlaczenie" },
    { "time",   EVIL_BLOCK_TIMESTAMP, "BLOCK_ERR_TIMESTAMP, rozlaczenie" },
    { "reward", EVIL_BLOCK_COINBASE,  "BLOCK_ERR_COINBASE, rozlaczenie" },
    { "orphan", EVIL_BLOCK_ORPHAN,    "CHAIN_ORPHAN, synchronizacja bez rozlaczenia" },
    { "format", EVIL_BLOCK_FORMAT,    "BLOCK_ERR_SIZE, rozlaczenie" },
};
#define EVIL_OPTION_COUNT (sizeof(EVIL_OPTIONS) / sizeof(EVIL_OPTIONS[0]))

static volatile bool s_busy = false;

// Zadanie budujące i wysyłające jeden blok z wadą
static void evil_task(void *arg) {
    const evil_option_t *option = (const evil_option_t *)arg;

    uint8_t payout[KRST_PUBKEY_SIZE];
    payout[0] = 0x02;
    memset(payout + 1, 0x11, KRST_PUBKEY_SIZE - 1);

    block_t *block = malloc(sizeof(block_t));
    if (block == NULL) {
        printf("[BLAD] Brak pamieci na blok.\r\n");
    } else {
        while (1) {
            chain_tip_t tip;
            chain_get_tip(&tip);
            evil_block_prepare(block, option->kind, &tip, payout, (uint32_t)time(NULL));
            if (!evil_block_needs_mining(option->kind) || miner_mine(block, tip.hash, NULL)) {
                break;
            }
        }

        int sent = node_p2p_broadcast(CMD_NEW_BLOCK, block, evil_block_wire_length(block, option->kind), NULL);
        printf("[EVIL] Blok '%s' wyslany do %d wezlow. Oczekiwana reakcja: %s\r\n",
               option->name, sent, option->expected);
        free(block);
    }

    s_busy = false;
    vTaskDelete(NULL);
}

// Wypisanie dostępnych wad
static void print_usage(void) {
    printf("Uzycie: evil <wada>   (np. evil pow)\r\n");
    printf("  %-7s    %s\r\n", "wada", "oczekiwana reakcja uczciwego wezla");
    for (size_t i = 0; i < EVIL_OPTION_COUNT; i++) {
        printf("  %-7s -> %s\r\n", EVIL_OPTIONS[i].name, EVIL_OPTIONS[i].expected);
    }
}

// Obsługa komendy evil
void node_evil_command(char *args) {
    char *name = strtok(args, " ");
    if (name == NULL) {
        print_usage();
        return;
    }

    const evil_option_t *option = NULL;
    for (size_t i = 0; i < EVIL_OPTION_COUNT; i++) {
        if (strcmp(name, EVIL_OPTIONS[i].name) == 0) {
            option = &EVIL_OPTIONS[i];
            break;
        }
    }
    if (option == NULL) {
        printf("[BLAD] Nieznana wada: %s\r\n", name);
        print_usage();
        return;
    }

    if (miner_is_running()) {
        printf("[BLAD] Najpierw zatrzymaj gornika: mine stop\r\n");
        return;
    }
    if (s_busy) {
        printf("[BLAD] Poprzedni zly blok jest jeszcze przygotowywany.\r\n");
        return;
    }

    s_busy = true;
    if (xTaskCreate(evil_task, "evil", EVIL_TASK_STACK, (void *)option, EVIL_TASK_PRIORITY, NULL) != pdPASS) {
        s_busy = false;
        printf("[BLAD] Brak pamieci na zadanie.\r\n");
        return;
    }

    if (evil_block_needs_mining(option->kind)) {
        printf("[OK] Kopanie bloku '%s' w tle, to potrwa jak zwykly blok.\r\n", option->name);
    }
}
