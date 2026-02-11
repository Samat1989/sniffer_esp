idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES driver esp_timer esp_event esp_netif esp_wifi nvs_flash esp_http_client esp-tls json esp_https_ota app_update)
