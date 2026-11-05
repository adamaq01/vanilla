#ifndef VANILLA_PI_CONFIG_H
#define VANILLA_PI_CONFIG_H

#include <stdint.h>
#include <vanilla.h>

#define VPI_CONSOLE_MAX_NAME 256
#define VPI_CONFIG_BUTTONMAP_SIZE 32
#define VPI_CONFIG_AXISMAP_SIZE 8
#define VPI_CONFIG_KEYMAP_SIZE 512
#define VPI_CONFIG_UNMAPPED -2

#define VPI_CONFIG_MAX_TRANSPORTS 8
#define VPI_CONFIG_MAX_TRANSPORT_OPTIONS 16
#define VPI_CONFIG_MAX_TRANSPORT_ID 64
#define VPI_CONFIG_MAX_OPTION_VALUE 256

// vanilla-pipe's transport, configured by server_address and wireless_interface
#define VPI_CONFIG_NETWORK_TRANSPORT "network"

typedef struct {
    char name[VPI_CONSOLE_MAX_NAME];
    vanilla_bssid_t bssid;
    vanilla_psk_t psk;
} vpi_console_entry_t;

typedef struct {
    char key[VPI_CONFIG_MAX_TRANSPORT_ID];
    char value[VPI_CONFIG_MAX_OPTION_VALUE];
} vpi_config_option_t;

// Option values stored for a transport, by key
typedef struct {
    char id[VPI_CONFIG_MAX_TRANSPORT_ID];
    uint8_t option_count;
    vpi_config_option_t options[VPI_CONFIG_MAX_TRANSPORT_OPTIONS];
} vpi_config_transport_t;

typedef struct {
    uint8_t connected_console_count;
    vpi_console_entry_t *connected_console_entries;
    uint32_t server_address;
    char wireless_interface[VPI_CONSOLE_MAX_NAME];

    // The transport to connect through, by id, VPI_CONFIG_NETWORK_TRANSPORT by
    // default, and the option values of the others
    char transport[VPI_CONFIG_MAX_TRANSPORT_ID];
    uint8_t transport_count;
    vpi_config_transport_t transports[VPI_CONFIG_MAX_TRANSPORTS];

    char recording_dir[1024];
    int connection_setup;
    int region;
    int swap_abxy;
    int keymap[VPI_CONFIG_KEYMAP_SIZE];
    int buttonmap[VPI_CONFIG_BUTTONMAP_SIZE];
    int axismap[VPI_CONFIG_AXISMAP_SIZE];
    int fullscreen;
    int cursor_in_fullscreen;
    int fast_drm;
    int force_software_decode;
    int autoconnect;
    float screen_brightness;
} vpi_config_t;

extern vpi_config_t vpi_config;

void vpi_config_init();
void vpi_config_free();
int vpi_config_add_console(vpi_console_entry_t *entry);
void vpi_config_rename_console(uint8_t index, const char *name);
void vpi_config_remove_console(uint8_t index);
void vpi_config_save();
void vpi_config_reset_default_controls();

/**
 * Whether the selected transport is vanilla-pipe's
 */
int vpi_config_uses_network_transport();

/**
 * The stored value of a transport's option, or NULL if there is none
 */
const char *vpi_config_get_transport_option(const char *id, const char *key);

#endif // VANILLA_PI_CONFIG_H
