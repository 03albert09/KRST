#include "node_wifi.h"
#include "node_p2p.h"

#include <string.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"

static const char *TAG = "NODE_WIFI";
static bool s_wifi_credentials_configured = false;
static bool s_sntp_started = false;
static volatile bool s_time_synced = false;

// Zapamiętanie pierwszej udanej synchronizacji zegara
static void on_time_synced(struct timeval *tv) {
    (void)tv;
    s_time_synced = true;
    ESP_LOGI(TAG, "Zegar zsynchronizowany przez SNTP.");
}

// Uruchomienie SNTP po pierwszym otrzymaniu adresu IP
static void start_sntp_once(void) {
    if (s_sntp_started) return;

    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    config.sync_cb = on_time_synced;

    if (esp_netif_sntp_init(&config) == ESP_OK) {
        s_sntp_started = true;
    } else {
        ESP_LOGW(TAG, "Nie udalo sie uruchomic SNTP.");
    }
}

// Sprawdzenie, czy zegar został zsynchronizowany przez SNTP
bool node_time_is_synced(void) {
    return s_time_synced;
}

// Obsługa zdarzeń WiFi i IP: ponowne łączenie i start SNTP po otrzymaniu adresu
static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        if (s_wifi_credentials_configured) {
            esp_wifi_connect();
        }
    } 
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_wifi_credentials_configured) {
            wifi_event_sta_disconnected_t* ev = (wifi_event_sta_disconnected_t*) event_data;
            ESP_LOGW(TAG, "Rozlaczono z WiFi (reason=%d, rssi=%d). Ponawianie proby polaczenia...",
                     ev->reason, ev->rssi);
            node_p2p_set_wifi_ready(false); 
            esp_wifi_connect();
        }
    } 
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Otrzymano IP: " IPSTR, IP2STR(&event->ip_info.ip));
        node_p2p_set_wifi_ready(true);
        start_sntp_once();
    }
}

// Inicjalizacja stosu sieciowego i WiFi w trybie stacji
void node_wifi_init(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL);
    
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    ESP_ERROR_CHECK(esp_wifi_start());
}

// Połączenie z siecią WiFi z wyłączonym PMF i oszczędzaniem energii, bo hotspoty w telefonach inaczej rozłączają ESP
void connect_wifi(const char* ssid, const char* pass) {
    wifi_config_t wifi_config = {0};
    strncpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char*)wifi_config.sta.password, pass, sizeof(wifi_config.sta.password) - 1);
    
    wifi_config.sta.pmf_cfg.capable = false;
    wifi_config.sta.pmf_cfg.required = false;

    s_wifi_credentials_configured = false;
    node_p2p_set_wifi_ready(false);
    esp_wifi_stop();

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

    ESP_ERROR_CHECK(esp_wifi_disable_pmf_config(WIFI_IF_STA));

    ESP_ERROR_CHECK(esp_wifi_set_protocol(WIFI_IF_STA,
                    WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N));

    s_wifi_credentials_configured = true;
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_ERROR_CHECK(esp_wifi_set_max_tx_power(80));

    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
}
