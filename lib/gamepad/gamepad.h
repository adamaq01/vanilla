#ifndef VANILLA_GAMEPAD_H
#define VANILLA_GAMEPAD_H

#include <pthread.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
typedef uint32_t in_addr_t;
typedef uint16_t in_port_t;
#else
#include <arpa/inet.h>
#include <errno.h>
#endif

#include "vanilla.h"
#include "vanilla_plugin/transport.h"

struct wpa_ctrl;

extern char wireless_interface[];

#define VANILLA_MAX_EVENT_COUNT 100
typedef struct
{
    vanilla_event_t events[VANILLA_MAX_EVENT_COUNT];
    size_t new_index;
    size_t used_index;
    int active;
    pthread_mutex_t mutex;
    pthread_cond_t waitcond;
} event_loop_t;

typedef struct
{
    event_loop_t *event_loop;
    const vanilla_transport_t *transport;
    void *transport_ctx;
} gamepad_context_t;

typedef struct thread_data_t thread_data_t;
typedef void (*thread_start_t)(thread_data_t *);
typedef struct thread_data_t
{
    uint32_t server_address;
    event_loop_t *event_loop;
    thread_start_t thread_start;
    void *thread_data;
    vanilla_bssid_t bssid;
    vanilla_psk_t psk;
} thread_data_t;

void sync_internal(thread_data_t *data);
void connect_as_gamepad_internal(thread_data_t *data);
int install_polkit_internal(thread_data_t *data, int install);
int send_to_console(gamepad_context_t *ctx, vanilla_channel_t channel, const void *data, size_t data_size);
int recv_from_console(gamepad_context_t *ctx, vanilla_channel_t channel, void *buf, size_t size);
int push_event(event_loop_t *loop, int type, const void *data, size_t size);
int get_event(event_loop_t *loop, vanilla_event_t *event, int wait);
int acquire_event(event_loop_t *loop, vanilla_event_t **event);
int release_event(event_loop_t *loop);

void init_event_buffer_arena();
void free_event_buffer_arena();
void *get_event_buffer();
void release_event_buffer(void *buffer);

#endif // VANILLA_GAMEPAD_H
