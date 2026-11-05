#ifndef VANILLA_PLUGIN_TRANSPORT_H
#define VANILLA_PLUGIN_TRANSPORT_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "capability.h"
#include "vanilla.h"

#define VANILLA_TRANSPORT_VERSION 1

/**
 * One per GamePad UDP port. The console's port is the GamePad's minus 100.
 */
typedef enum {
    VANILLA_CHANNEL_MSG, // 50110
    VANILLA_CHANNEL_VID, // 50120
    VANILLA_CHANNEL_AUD, // 50121
    VANILLA_CHANNEL_HID, // 50122
    VANILLA_CHANNEL_CMD, // 50123
    VANILLA_CHANNEL_COUNT
} vanilla_channel_t;

/**
 * Moves GamePad datagrams between vanilla and the console, and handles pairing
 * and connecting. It knows nothing about the GamePad protocol.
 *
 * Errors are the negative VANILLA_ERR_* codes. No call blocks longer than its
 * timeout (plus a few milliseconds), and calls without one return promptly.
 * Datagrams keep their boundaries and may be dropped, as with UDP: a transport
 * that queues them keeps its queues shallow and drops the oldest rather than
 * delay the ones after it.
 */
typedef struct vanilla_transport {
    vanilla_capability_t base; // Type VANILLA_CAPABILITY_TRANSPORT, version VANILLA_TRANSPORT_VERSION

    /**
     * Pairing: start, then poll until it returns 1 (paired, `result` written)
     * or < 0 (failed). 0 means nothing happened within `timeout_ms`.
     */
    int (*start_sync)(void *ctx, uint16_t code);
    int (*poll_sync)(void *ctx, uint32_t timeout_ms, vanilla_connection_t *result);

    /**
     * Connection: start, then poll for link changes for the rest of the session.
     * Returns 1 if the link changed (`link_up` written), 0 if not within
     * `timeout_ms`, or < 0 if the transport is gone, which ends the session.
     */
    int (*start_connect)(void *ctx, const vanilla_connection_t *console);
    int (*poll_link)(void *ctx, uint32_t timeout_ms, int *link_up);

    /**
     * Datagrams on a channel (vanilla_channel_t). `send` returns VANILLA_SUCCESS
     * or an error if the datagram was dropped. `recv` returns the datagram's
     * size (truncated to `size`), 0 if none arrived within `timeout_ms`, or an
     * error.
     */
    int (*send)(void *ctx, uint32_t channel, const void *data, size_t size);
    int (*recv)(void *ctx, uint32_t channel, void *buf, size_t size, uint32_t timeout_ms);
} vanilla_transport_t;

#if defined(__cplusplus)
}
#endif

#endif // VANILLA_PLUGIN_TRANSPORT_H
