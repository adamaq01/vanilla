#define _GNU_SOURCE

#include "network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
typedef uint32_t in_addr_t;
typedef uint16_t in_port_t;
#else
#include <arpa/inet.h>
#include <errno.h>
#endif

#include "../pipe/def.h"
#include "../pipe/ports.h"
#include "util.h"

// The Wii U always places itself at this address
#define CONSOLE_ADDRESS "192.168.1.10"

// How many times a command is sent before giving up on vanilla-pipe, how long
// to wait for each reply, and how long to wait before sending it again
static const int MAX_PIPE_RETRY = 5;
#define PIPE_REPLY_TIMEOUT_MS 2000
#define PIPE_RETRY_DELAY_MS 1000

// How long to wait after vanilla-pipe reports a connection before opening the
// data sockets
#define LINK_DELAY_MS 1000

#define DEFAULT_RECV_TIMEOUT_MS 250

typedef enum {
    PIPE_IDLE,    // No command sent yet
    PIPE_BINDING, // Waiting for vanilla-pipe to accept the command
    PIPE_BOUND,   // vanilla-pipe is carrying out the command
    PIPE_LINKING, // Connected, waiting before opening the data sockets
    PIPE_LINKED,  // Data sockets open
} pipe_state_t;

typedef struct {
    in_addr_t server_address;
    char wireless_interface[128];

    int pipe_skt;
    uint32_t pipe_timeout_ms;
    pipe_state_t state;
    vanilla_pipe_command_t cmd;
    size_t cmd_size;
    int attempts;
    int busy;
    int needs_unbind;
    size_t sent_at;
    size_t resend_at;
    size_t last_message_at;
    size_t linking_since;
    size_t last_wait_log;

    int data_skt[VANILLA_CHANNEL_COUNT];
    uint32_t data_timeout_ms[VANILLA_CHANNEL_COUNT];
    struct sockaddr_in console_addr[VANILLA_CHANNEL_COUNT];
} network_ctx_t;

static inline int skterr()
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

static int is_timeout(int err)
{
#ifdef _WIN32
    return err == WSAETIMEDOUT;
#else
    return err == EAGAIN || err == EWOULDBLOCK;
#endif
}

static void sleep_ms(uint32_t ms)
{
    usleep(ms * 1000);
}

static uint16_t channel_port(uint32_t channel)
{
    switch (channel) {
    case VANILLA_CHANNEL_MSG: return PORT_MSG;
    case VANILLA_CHANNEL_VID: return PORT_VID;
    case VANILLA_CHANNEL_AUD: return PORT_AUD;
    case VANILLA_CHANNEL_HID: return PORT_HID;
    case VANILLA_CHANNEL_CMD: return PORT_CMD;
    }
    return 0;
}

static void create_sockaddr(struct sockaddr_in *addr, in_addr_t inaddr, uint16_t port)
{
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = inaddr;
}

static void set_socket_rcvtimeo(int skt, uint64_t microseconds)
{
#ifdef _WIN32
    DWORD millis = microseconds / 1000;
    setsockopt(skt, SOL_SOCKET, SO_RCVTIMEO, (const char *) &millis, sizeof(millis));
#else
    struct timeval tv = {0};
    tv.tv_sec = microseconds / 1000000;
    tv.tv_usec = microseconds % 1000000;
    setsockopt(skt, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif // _WIN32
}

static int create_socket(network_ctx_t *ctx, int *socket_out, in_port_t port, int pipe)
{
    struct sockaddr_in addr;

    in_addr_t bind_address = (pipe && ctx->server_address == VANILLA_ADDRESS_LOCAL) ? htonl(INADDR_LOOPBACK) : INADDR_ANY;

    create_sockaddr(&addr, bind_address, port);

    int skt = socket(AF_INET, SOCK_DGRAM, 0);
    if (skt == -1) {
        vanilla_log("FAILED TO CREATE SOCKET: %i", skterr());
        return VANILLA_ERR_BAD_SOCKET;
    }

    if (bind(skt, (const struct sockaddr *) &addr, sizeof(addr)) == -1) {
        vanilla_log("FAILED TO BIND PORT %u: %i", port, skterr());
        close(skt);
        return VANILLA_ERR_BAD_SOCKET;
    }

    set_socket_rcvtimeo(skt, DEFAULT_RECV_TIMEOUT_MS * 1000);

#if !defined(_WIN32) && !defined(__APPLE__) && !defined(ANDROID)
    if (!pipe && ctx->server_address == VANILLA_ADDRESS_LOCAL) {
        // Bind to wireless device
        setsockopt(skt, SOL_SOCKET, SO_BINDTODEVICE, ctx->wireless_interface, strlen(ctx->wireless_interface));
    }
#endif

    (*socket_out) = skt;

    return VANILLA_SUCCESS;
}

// Returns the datagram's size, 0 on timeout, or -1 on error with `error` set
static int recv_with_timeout(int skt, uint32_t *current_timeout_ms, void *buf, size_t size, uint32_t timeout_ms, int *error)
{
    // A zero timeout would block forever
    if (timeout_ms == 0) {
        timeout_ms = 1;
    }

    if (*current_timeout_ms != timeout_ms) {
        set_socket_rcvtimeo(skt, (uint64_t) timeout_ms * 1000);
        *current_timeout_ms = timeout_ms;
    }

    ssize_t read_size = recv(skt, (char *) buf, size, 0);
    if (read_size < 0) {
        int err = skterr();
        if (is_timeout(err)) {
            return 0;
        }
        *error = err;
        return -1;
    }

    return read_size;
}

static void get_pipe_sockaddr(network_ctx_t *ctx, struct sockaddr_in *addr)
{
    in_addr_t pipe_addr = (ctx->server_address == VANILLA_ADDRESS_LOCAL) ? htonl(INADDR_LOOPBACK) : ctx->server_address;
    create_sockaddr(addr, pipe_addr, VANILLA_PIPE_CMD_SERVER_PORT);
}

static int recv_from_pipe(network_ctx_t *ctx, vanilla_pipe_command_t *cmd, uint32_t timeout_ms, int *error)
{
    return recv_with_timeout(ctx->pipe_skt, &ctx->pipe_timeout_ms, cmd, sizeof(*cmd), timeout_ms, error);
}

static int send_command(network_ctx_t *ctx)
{
    struct sockaddr_in addr;
    get_pipe_sockaddr(ctx, &addr);

    if (sendto(ctx->pipe_skt, (const char *) &ctx->cmd, ctx->cmd_size, 0, (const struct sockaddr *) &addr, sizeof(addr)) == -1) {
        vanilla_log("Failed to write control code to socket: %i", skterr());
        vanilla_log("FAILED TO BIND TO PIPE");
        return VANILLA_ERR_PIPE_UNRESPONSIVE;
    }

    // vanilla-pipe may act on it even if its reply gets lost
    ctx->needs_unbind = 1;

    ctx->attempts++;
    ctx->sent_at = get_millis();
    ctx->resend_at = 0;

    return VANILLA_SUCCESS;
}

static void send_unbind(network_ctx_t *ctx)
{
    struct sockaddr_in addr;
    get_pipe_sockaddr(ctx, &addr);

    vanilla_pipe_command_t cmd;
    cmd.control_code = VANILLA_PIPE_CC_UNBIND;
    if (sendto(ctx->pipe_skt, (const char *) &cmd, sizeof(cmd.control_code), 0, (const struct sockaddr *) &addr, sizeof(addr)) == -1) {
        vanilla_log("Failed to write control code to socket: %i", skterr());
    }
}

static int start_command(network_ctx_t *ctx, const vanilla_pipe_command_t *cmd, size_t cmd_size)
{
    if (ctx->state != PIPE_IDLE) {
        return VANILLA_ERR_GENERIC;
    }

    int ret = create_socket(ctx, &ctx->pipe_skt, VANILLA_PIPE_CMD_CLIENT_PORT, 1);
    if (ret != VANILLA_SUCCESS) {
        return ret;
    }

    ctx->cmd = *cmd;
    ctx->cmd_size = cmd_size;
    ctx->state = PIPE_BINDING;

    return send_command(ctx);
}

// Called when an attempt to send the command got no acknowledgement
static int retry_command(network_ctx_t *ctx)
{
    if (ctx->attempts >= MAX_PIPE_RETRY) {
        ctx->needs_unbind = 0;
        if (ctx->busy) {
            vanilla_log("PIPE IS BUSY");
            return VANILLA_ERR_BUSY;
        }
        vanilla_log("FAILED TO BIND TO PIPE");
        return VANILLA_ERR_PIPE_UNRESPONSIVE;
    }

    if (ctx->busy) {
        vanilla_log("PIPE BUSY, RETRYING");
    }

    ctx->resend_at = get_millis() + PIPE_RETRY_DELAY_MS;
    return 0;
}

/**
 * Waits for vanilla-pipe to accept the command, sending it again as needed.
 * Returns 1 once accepted, 0 if still waiting, or an error.
 */
static int pump_bind(network_ctx_t *ctx, uint32_t timeout_ms)
{
    size_t now = get_millis();

    if (ctx->resend_at) {
        if (now < ctx->resend_at) {
            sleep_ms(MIN(timeout_ms, ctx->resend_at - now));
            return 0;
        }
        return send_command(ctx);
    }

    size_t deadline = ctx->sent_at + PIPE_REPLY_TIMEOUT_MS;
    uint32_t wait = (now < deadline) ? MIN(timeout_ms, deadline - now) : 0;

    vanilla_pipe_command_t reply;
    int err = 0;
    int read_size = recv_from_pipe(ctx, &reply, wait, &err);
    if (read_size > 0) {
        if (reply.control_code == VANILLA_PIPE_CC_BIND_ACK) {
            ctx->state = PIPE_BOUND;
            ctx->last_message_at = get_millis();
            return 1;
        }

        ctx->busy = (reply.control_code == VANILLA_PIPE_CC_BUSY);
        if (!ctx->busy) {
            vanilla_log("UNEXPECTED PIPE REPLY: 0x%02x", reply.control_code);
        }
    } else if (read_size == 0 && get_millis() < deadline) {
        return 0;
    } else {
        ctx->busy = 0;
        vanilla_log("STILL WAITING FOR REPLY: %i", read_size < 0 ? err : 0);
    }

    return retry_command(ctx);
}

static int open_data_sockets(network_ctx_t *ctx)
{
    in_addr_t console = (ctx->server_address == VANILLA_ADDRESS_LOCAL) ? inet_addr(CONSOLE_ADDRESS) : ctx->server_address;

    for (int i = 0; i < VANILLA_CHANNEL_COUNT; i++) {
        uint16_t port = channel_port(i);
        int ret = create_socket(ctx, &ctx->data_skt[i], port, 0);
        if (ret != VANILLA_SUCCESS) {
            for (int j = 0; j < i; j++) {
                close(ctx->data_skt[j]);
                ctx->data_skt[j] = -1;
            }
            return ret;
        }

        ctx->data_timeout_ms[i] = DEFAULT_RECV_TIMEOUT_MS;
        create_sockaddr(&ctx->console_addr[i], console, port - 100);
    }

    return VANILLA_SUCCESS;
}

static int parse_server(const char *value, in_addr_t *address)
{
    if (!strcmp(value, "local")) {
        *address = VANILLA_ADDRESS_LOCAL;
        return 1;
    }

    *address = inet_addr(value);
    return *address != INADDR_NONE;
}

static int network_validate(const char *const *option_values, size_t *invalid_option)
{
    in_addr_t address;
    if (!parse_server(option_values[NETWORK_OPTION_SERVER], &address)) {
        *invalid_option = NETWORK_OPTION_SERVER;
        return VANILLA_ERR_INVALID_ARGUMENT;
    }

    return VANILLA_SUCCESS;
}

static int network_open(const char *const *option_values, void **out)
{
    in_addr_t server_address;
    if (!parse_server(option_values[NETWORK_OPTION_SERVER], &server_address)) {
        return VANILLA_ERR_INVALID_ARGUMENT;
    }

    network_ctx_t *ctx = calloc(1, sizeof(network_ctx_t));
    if (!ctx) {
        return VANILLA_ERR_OUT_OF_MEMORY;
    }

    ctx->server_address = server_address;
    snprintf(ctx->wireless_interface, sizeof(ctx->wireless_interface), "%s", option_values[NETWORK_OPTION_INTERFACE]);
    ctx->pipe_skt = -1;
    ctx->state = PIPE_IDLE;
    for (int i = 0; i < VANILLA_CHANNEL_COUNT; i++) {
        ctx->data_skt[i] = -1;
    }

    *out = ctx;
    return VANILLA_SUCCESS;
}

static void network_close(void *x)
{
    network_ctx_t *ctx = (network_ctx_t *) x;

    for (int i = 0; i < VANILLA_CHANNEL_COUNT; i++) {
        if (ctx->data_skt[i] != -1) {
            close(ctx->data_skt[i]);
        }
    }

    if (ctx->pipe_skt != -1) {
        // Disconnect from pipe if necessary
        if (ctx->needs_unbind) {
            send_unbind(ctx);
        }
        close(ctx->pipe_skt);
    }

    free(ctx);
}

static int network_start_sync(void *x, uint16_t code)
{
    network_ctx_t *ctx = (network_ctx_t *) x;

    vanilla_pipe_command_t cmd;
    cmd.control_code = VANILLA_PIPE_CC_SYNC;
    cmd.sync.code = htons(code);

    return start_command(ctx, &cmd, sizeof(cmd.control_code) + sizeof(cmd.sync));
}

static int network_poll_sync(void *x, uint32_t timeout_ms, vanilla_connection_t *result)
{
    network_ctx_t *ctx = (network_ctx_t *) x;

    if (ctx->state == PIPE_BINDING) {
        int ret = pump_bind(ctx, timeout_ms);
        return (ret < 0) ? ret : 0;
    }

    vanilla_pipe_command_t cmd;
    int err;
    if (recv_from_pipe(ctx, &cmd, timeout_ms, &err) > 0) {
        switch (cmd.control_code) {
        case VANILLA_PIPE_CC_STATUS:
        {
            // vanilla-pipe only reports failures this way
            int32_t status = (int32_t) ntohl(cmd.status.status);
            ctx->needs_unbind = 0;
            return (status < 0) ? status : VANILLA_ERR_GENERIC;
        }
        case VANILLA_PIPE_CC_SYNC_SUCCESS:
            result->bssid = cmd.connection.bssid;
            result->psk = cmd.connection.psk;
            ctx->needs_unbind = 0;
            return 1;
        case VANILLA_PIPE_CC_PING:
            // Pipe is still responsive but hasn't found anything yet
            ctx->last_message_at = get_millis();
            break;
        }
    }

    if (get_millis() - ctx->last_message_at >= MAX_PIPE_RETRY * PIPE_REPLY_TIMEOUT_MS) {
        ctx->needs_unbind = 0;
        return VANILLA_ERR_PIPE_UNRESPONSIVE;
    }

    return 0;
}

static int network_start_connect(void *x, const vanilla_connection_t *console)
{
    network_ctx_t *ctx = (network_ctx_t *) x;

    vanilla_pipe_command_t cmd;
    cmd.control_code = VANILLA_PIPE_CC_CONNECT;
    cmd.connection = *console;

    return start_command(ctx, &cmd, sizeof(cmd.control_code) + sizeof(cmd.connection));
}

static int wait_for_connection(network_ctx_t *ctx, uint32_t timeout_ms)
{
    vanilla_pipe_command_t cmd;
    int err;
    int read_size = recv_from_pipe(ctx, &cmd, timeout_ms, &err);
    if (read_size < 0) {
        vanilla_log("FAILED TO GET CONNECTED STATE: %i", err);
        return VANILLA_ERR_PIPE_UNRESPONSIVE;
    }

    if (read_size > 0 && cmd.control_code == VANILLA_PIPE_CC_CONNECTED) {
        ctx->state = PIPE_LINKING;
        ctx->linking_since = get_millis();
        return 0;
    }

    size_t now = get_millis();
    if (now - ctx->last_wait_log >= PIPE_REPLY_TIMEOUT_MS) {
        vanilla_log("STILL WAITING FOR CONNECTED STATE");
        ctx->last_wait_log = now;
    }

    return 0;
}

static int finish_linking(network_ctx_t *ctx, uint32_t timeout_ms, int *link_up)
{
    size_t elapsed = get_millis() - ctx->linking_since;
    if (elapsed < LINK_DELAY_MS) {
        sleep_ms(MIN(timeout_ms, LINK_DELAY_MS - elapsed));
        if (get_millis() - ctx->linking_since < LINK_DELAY_MS) {
            return 0;
        }
    }

    int ret = open_data_sockets(ctx);
    if (ret != VANILLA_SUCCESS) {
        return ret;
    }

    ctx->state = PIPE_LINKED;
    *link_up = 1;
    return 1;
}

static int relay_link_state(network_ctx_t *ctx, uint32_t timeout_ms, int *link_up)
{
    vanilla_pipe_command_t cmd;
    int err;
    if (recv_from_pipe(ctx, &cmd, timeout_ms, &err) > 0) {
        switch (cmd.control_code) {
        case VANILLA_PIPE_CC_DISCONNECTED:
            *link_up = 0;
            return 1;
        case VANILLA_PIPE_CC_CONNECTED:
            *link_up = 1;
            return 1;
        }
    }

    return 0;
}

static int network_poll_link(void *x, uint32_t timeout_ms, int *link_up)
{
    network_ctx_t *ctx = (network_ctx_t *) x;

    switch (ctx->state) {
    case PIPE_BINDING:
    {
        int ret = pump_bind(ctx, timeout_ms);
        return (ret < 0) ? ret : 0;
    }
    case PIPE_BOUND:
        return wait_for_connection(ctx, timeout_ms);
    case PIPE_LINKING:
        return finish_linking(ctx, timeout_ms, link_up);
    case PIPE_LINKED:
        return relay_link_state(ctx, timeout_ms, link_up);
    case PIPE_IDLE:
        break;
    }

    return VANILLA_ERR_GENERIC;
}

static int network_send(void *x, uint32_t channel, const void *data, size_t size)
{
    network_ctx_t *ctx = (network_ctx_t *) x;

    if (channel >= VANILLA_CHANNEL_COUNT || ctx->data_skt[channel] == -1) {
        return VANILLA_ERR_INVALID_ARGUMENT;
    }

    int skt = ctx->data_skt[channel];
    ssize_t sent = sendto(skt, (const char *) data, size, 0, (const struct sockaddr *) &ctx->console_addr[channel], sizeof(ctx->console_addr[channel]));
    if (sent == -1) {
		int err = skterr();
		if (err != 111) { // 111 is connection refused, occurs if we lose connection, but we'll already know that for other reasons so we don't need to spam the console with this error
			vanilla_log("Failed to send to Wii U socket: fd: %d, errno: %i", skt, err);
		}
        return VANILLA_ERR_BAD_SOCKET;
    }

    return VANILLA_SUCCESS;
}

static int network_recv(void *x, uint32_t channel, void *buf, size_t size, uint32_t timeout_ms)
{
    network_ctx_t *ctx = (network_ctx_t *) x;

    if (channel >= VANILLA_CHANNEL_COUNT || ctx->data_skt[channel] == -1) {
        return VANILLA_ERR_INVALID_ARGUMENT;
    }

    int err;
    int read_size = recv_with_timeout(ctx->data_skt[channel], &ctx->data_timeout_ms[channel], buf, size, timeout_ms, &err);
    return (read_size < 0) ? VANILLA_ERR_BAD_SOCKET : read_size;
}

static const vanilla_option_t network_options[NETWORK_OPTION_COUNT] = {
    {"server", "Server", VANILLA_OPTION_STRING, "local", NULL},
    {"interface", "Wireless interface", VANILLA_OPTION_STRING, "", NULL},
};

const vanilla_transport_t network_transport = {
    .base = {
        .struct_size = sizeof(vanilla_transport_t),
        .type = VANILLA_CAPABILITY_TRANSPORT,
        .version = VANILLA_TRANSPORT_VERSION,
        .id = "network",
        .name = "Network (vanilla-pipe)",
        .options = network_options,
        .option_count = NETWORK_OPTION_COUNT,
        .list_choices = NULL,
        .validate = network_validate,
        .open = network_open,
        .close = network_close,
    },
    .start_sync = network_start_sync,
    .poll_sync = network_poll_sync,
    .start_connect = network_start_connect,
    .poll_link = network_poll_link,
    .send = network_send,
    .recv = network_recv,
};

void network_format_server(uint32_t server_address, char *buf, size_t size)
{
    if (server_address == VANILLA_ADDRESS_LOCAL) {
        snprintf(buf, size, "local");
        return;
    }

    // In network byte order, like inet_addr() returns it
    const uint8_t *b = (const uint8_t *) &server_address;
    snprintf(buf, size, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

int network_install_polkit(uint32_t server_address, int install)
{
    char server[16];
    network_format_server(server_address, server, sizeof(server));
    const char *values[NETWORK_OPTION_COUNT] = {server, ""};

    void *x;
    int ret = network_open(values, &x);
    if (ret != VANILLA_SUCCESS) {
        return ret;
    }
    network_ctx_t *ctx = (network_ctx_t *) x;

    vanilla_pipe_command_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.control_code = install ? VANILLA_PIPE_CC_INSTALL_POLKIT : VANILLA_PIPE_CC_UNINSTALL_POLKIT;

    // No interrupt is required here because VANILLA_PIPE_CC_INSTALL_POLKIT
    // does not start a thread in the pipe
    ret = start_command(ctx, &cmd, sizeof(cmd.control_code) + sizeof(cmd.connection));
    while (ret == VANILLA_SUCCESS) {
        int r = pump_bind(ctx, PIPE_REPLY_TIMEOUT_MS);
        if (r < 0) {
            ret = r;
        } else if (r > 0) {
            break;
        }
    }

    network_close(ctx);
    return ret;
}
