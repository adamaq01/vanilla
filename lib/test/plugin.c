/**
 * Unit test for registering plugins and running a transport through a pairing
 * and a session
 */

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "vanilla.h"
#include "vanilla_plugin/plugin.h"

// What vanilla did with the fake transport
static pthread_mutex_t fake_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct {
    int opened;
    int closed;
    char mode[16];
    uint16_t sync_code;
    uint8_t console_bssid;
    int sync_polls;
    int link_polls;
    int sends[VANILLA_CHANNEL_COUNT];
    int recvs[VANILLA_CHANNEL_COUNT];
    int calls_after_close;
} fake;

static int fake_ctx;

static void sleep_ms(uint32_t ms)
{
    usleep(ms * 1000);
}

static const char *const fake_modes[] = {"good", "other", NULL};

static const vanilla_option_t fake_options[] = {
    {"mode", "Mode", VANILLA_OPTION_CHOICE, "good", fake_modes},
};

static int fake_validate(const char *const *option_values, size_t *invalid_option)
{
    for (size_t i = 0; fake_modes[i]; i++) {
        if (!strcmp(option_values[0], fake_modes[i])) {
            return VANILLA_SUCCESS;
        }
    }
    *invalid_option = 0;
    return VANILLA_ERR_INVALID_ARGUMENT;
}

static int fake_open(const char *const *option_values, void **ctx)
{
    pthread_mutex_lock(&fake_mutex);
    fake.opened++;
    snprintf(fake.mode, sizeof(fake.mode), "%s", option_values[0]);
    pthread_mutex_unlock(&fake_mutex);

    *ctx = &fake_ctx;
    return VANILLA_SUCCESS;
}

static void fake_close(void *ctx)
{
    pthread_mutex_lock(&fake_mutex);
    if (ctx == &fake_ctx) {
        fake.closed++;
    }
    pthread_mutex_unlock(&fake_mutex);
}

static int fake_start_sync(void *ctx, uint16_t code)
{
    fake.sync_code = code;
    return VANILLA_SUCCESS;
}

// Pairs on the third poll
static int fake_poll_sync(void *ctx, uint32_t timeout_ms, vanilla_connection_t *result)
{
    sleep_ms(10);
    if (++fake.sync_polls < 3) {
        return 0;
    }

    memset(result->bssid.bssid, 0xAB, sizeof(result->bssid.bssid));
    memset(result->psk.psk, 0xCD, sizeof(result->psk.psk));
    return 1;
}

static int fake_start_connect(void *ctx, const vanilla_connection_t *console)
{
    fake.console_bssid = console->bssid.bssid[0];
    return VANILLA_SUCCESS;
}

// The link comes up, goes down for a moment, and comes back
static int fake_poll_link(void *ctx, uint32_t timeout_ms, int *link_up)
{
    sleep_ms(10);
    switch (++fake.link_polls) {
    case 2:
        *link_up = 1;
        return 1;
    case 30:
        *link_up = 0;
        return 1;
    case 31:
        *link_up = 1;
        return 1;
    }
    return 0;
}

static int fake_send(void *ctx, uint32_t channel, const void *data, size_t size)
{
    pthread_mutex_lock(&fake_mutex);
    if (fake.closed) {
        fake.calls_after_close++;
    }
    fake.sends[channel]++;
    pthread_mutex_unlock(&fake_mutex);

    return VANILLA_SUCCESS;
}

static int fake_recv(void *ctx, uint32_t channel, void *buf, size_t size, uint32_t timeout_ms)
{
    pthread_mutex_lock(&fake_mutex);
    if (fake.closed) {
        fake.calls_after_close++;
    }
    fake.recvs[channel]++;
    pthread_mutex_unlock(&fake_mutex);

    sleep_ms(timeout_ms < 10 ? timeout_ms : 10);
    return 0;
}

#define FAKE_TRANSPORT(transport_id, recv_function) { \
    .base = { \
        .struct_size = sizeof(vanilla_transport_t), \
        .type = VANILLA_CAPABILITY_TRANSPORT, \
        .version = VANILLA_TRANSPORT_VERSION, \
        .id = transport_id, \
        .name = "Fake", \
        .options = fake_options, \
        .option_count = sizeof(fake_options) / sizeof(fake_options[0]), \
        .validate = fake_validate, \
        .open = fake_open, \
        .close = fake_close, \
    }, \
    .start_sync = fake_start_sync, \
    .poll_sync = fake_poll_sync, \
    .start_connect = fake_start_connect, \
    .poll_link = fake_poll_link, \
    .send = fake_send, \
    .recv = recv_function, \
}

static const vanilla_transport_t fake_transport = FAKE_TRANSPORT("fake", fake_recv);
static const vanilla_transport_t duplicate_transport = FAKE_TRANSPORT("network", fake_recv);
static const vanilla_transport_t incomplete_transport = FAKE_TRANSPORT("incomplete", NULL);

static const vanilla_capability_t unknown_capability = {
    .struct_size = sizeof(vanilla_capability_t),
    .type = 99,
    .version = 1,
    .id = "unknown",
    .name = "Unknown",
};

static const vanilla_capability_t *const fake_capabilities[] = {
    &fake_transport.base,
    &unknown_capability,
    &duplicate_transport.base,
    &incomplete_transport.base,
};

static const vanilla_plugin_t fake_plugin = {
    .struct_size = sizeof(vanilla_plugin_t),
    .abi_version = VANILLA_PLUGIN_ABI_VERSION,
    .id = "test",
    .name = "Test",
    .version = "1",
    .capabilities = fake_capabilities,
    .capability_count = sizeof(fake_capabilities) / sizeof(fake_capabilities[0]),
};

static const vanilla_plugin_t future_plugin = {
    .struct_size = sizeof(vanilla_plugin_t),
    .abi_version = VANILLA_PLUGIN_ABI_VERSION + 1,
    .id = "future",
    .name = "Future",
    .version = "1",
    .capabilities = fake_capabilities,
    .capability_count = 1,
};

static const vanilla_plugin_t *fake_entry(const vanilla_host_t *host)
{
    host->log("fake plugin loading");
    return &fake_plugin;
}

static const vanilla_plugin_t *future_entry(const vanilla_host_t *host)
{
    return &future_plugin;
}

static const vanilla_plugin_t *declining_entry(const vanilla_host_t *host)
{
    return NULL;
}

static const vanilla_transport_t *find_transport(const char *id)
{
    for (size_t i = 0; i < vanilla_get_transport_count(); i++) {
        const vanilla_transport_t *t = vanilla_get_transport(i);
        if (!strcmp(t->base.id, id)) {
            return t;
        }
    }
    return NULL;
}

// Waits for an event of `type`, copying its data, and frees the others
static int wait_for_event(int type, void *data, size_t size, uint32_t timeout_ms)
{
    for (uint32_t waited = 0; waited < timeout_ms; waited += 10) {
        vanilla_event_t event;
        while (vanilla_poll_event(&event)) {
            int match = (event.type == type);
            if (match) {
                memcpy(data, event.data, event.size < size ? event.size : size);
            }
            vanilla_free_event(&event);
            if (match) {
                return 1;
            }
        }
        sleep_ms(10);
    }
    return 0;
}

static int wait_for_error(int expected, uint32_t timeout_ms)
{
    int error;
    while (wait_for_event(VANILLA_EVENT_ERROR, &error, sizeof(error), timeout_ms)) {
        if (error == expected) {
            return 1;
        }
        printf("(got error %i while waiting for %i) ", error, expected);
    }
    return 0;
}

int builtin_transport()
{
    const vanilla_transport_t *network = find_transport("network");
    if (!network || network->base.type != VANILLA_CAPABILITY_TRANSPORT || network->base.version != VANILLA_TRANSPORT_VERSION) {
        printf("FAIL (no built-in network transport)\n");
        return 1;
    }

    printf("SUCCESS\n");
    return 0;
}

int rejected_plugins()
{
    size_t count = vanilla_get_transport_count();

    if (vanilla_register_plugin(NULL) == VANILLA_SUCCESS) {
        printf("FAIL (registered a NULL entry)\n");
        return 1;
    }

    if (vanilla_register_plugin(declining_entry) == VANILLA_SUCCESS) {
        printf("FAIL (registered a plugin that declined)\n");
        return 1;
    }

    if (vanilla_register_plugin(future_entry) == VANILLA_SUCCESS) {
        printf("FAIL (registered a plugin built for another ABI)\n");
        return 1;
    }

    if (vanilla_get_transport_count() != count) {
        printf("FAIL (rejected plugins added transports)\n");
        return 1;
    }

    printf("SUCCESS\n");
    return 0;
}

int registered_plugin()
{
    size_t count = vanilla_get_transport_count();

    if (vanilla_register_plugin(fake_entry) != VANILLA_SUCCESS) {
        printf("FAIL (couldn't register plugin)\n");
        return 1;
    }

    // Only the valid transport with a new id is kept
    if (vanilla_get_transport_count() != count + 1 || find_transport("fake") != &fake_transport) {
        printf("FAIL (expected 1 more transport, got %zu)\n", vanilla_get_transport_count() - count);
        return 1;
    }

    if (find_transport("network") == &duplicate_transport || find_transport("incomplete")) {
        printf("FAIL (kept an invalid transport)\n");
        return 1;
    }

    if (vanilla_register_plugin(fake_entry) == VANILLA_SUCCESS || vanilla_get_transport_count() != count + 1) {
        printf("FAIL (registered the same plugin twice)\n");
        return 1;
    }

    printf("SUCCESS\n");
    return 0;
}

int selected_transport()
{
    if (vanilla_set_transport("missing", NULL) == VANILLA_SUCCESS) {
        printf("FAIL (selected a missing transport)\n");
        return 1;
    }

    const char *broken[] = {"broken"};
    if (vanilla_set_transport("fake", broken) == VANILLA_SUCCESS) {
        printf("FAIL (selected a transport with invalid options)\n");
        return 1;
    }

    if (vanilla_set_transport("fake", NULL) != VANILLA_SUCCESS) {
        printf("FAIL (couldn't select a transport with its defaults)\n");
        return 1;
    }

    printf("SUCCESS\n");
    return 0;
}

int pairing()
{
    memset(&fake, 0, sizeof(fake));

    if (vanilla_sync(1234) != VANILLA_SUCCESS) {
        printf("FAIL (couldn't start pairing)\n");
        return 1;
    }

    vanilla_sync_event_t result;
    int got_result = wait_for_event(VANILLA_EVENT_SYNC, &result, sizeof(result), 5000);

    vanilla_stop();

    if (!got_result || result.status != VANILLA_SUCCESS || result.data.bssid.bssid[0] != 0xAB || result.data.psk.psk[0] != 0xCD) {
        printf("FAIL (no pairing result)\n");
        return 1;
    }

    if (fake.opened != 1 || fake.closed != 1 || fake.sync_code != 1234 || strcmp(fake.mode, "good")) {
        printf("FAIL (opened %i, closed %i, code %u, mode %s)\n", fake.opened, fake.closed, fake.sync_code, fake.mode);
        return 1;
    }

    printf("SUCCESS\n");
    return 0;
}

int session()
{
    memset(&fake, 0, sizeof(fake));

    const char *values[] = {"other"};
    if (vanilla_set_transport("fake", values) != VANILLA_SUCCESS) {
        printf("FAIL (couldn't select the transport)\n");
        return 1;
    }

    vanilla_bssid_t bssid;
    vanilla_psk_t psk;
    memset(&bssid, 0x12, sizeof(bssid));
    memset(&psk, 0x34, sizeof(psk));

    if (vanilla_start(bssid, psk) != VANILLA_SUCCESS) {
        printf("FAIL (couldn't start the session)\n");
        return 1;
    }

    int link_events = wait_for_error(VANILLA_ERR_CONNECTED, 5000)
        && wait_for_error(VANILLA_ERR_DISCONNECTED, 5000)
        && wait_for_error(VANILLA_ERR_CONNECTED, 5000);

    // Let the GamePad threads run for a moment
    sleep_ms(200);

    vanilla_stop();

    if (!link_events) {
        printf("FAIL (missing link events)\n");
        return 1;
    }

    if (fake.opened != 1 || fake.closed != 1 || fake.console_bssid != 0x12 || strcmp(fake.mode, "other")) {
        printf("FAIL (opened %i, closed %i, bssid %02x, mode %s)\n", fake.opened, fake.closed, fake.console_bssid, fake.mode);
        return 1;
    }

    if (!fake.sends[VANILLA_CHANNEL_HID] || !fake.recvs[VANILLA_CHANNEL_VID] || !fake.recvs[VANILLA_CHANNEL_AUD] || !fake.recvs[VANILLA_CHANNEL_CMD]) {
        printf("FAIL (channels unused: %i HID sends, %i VID, %i AUD, %i CMD receives)\n",
               fake.sends[VANILLA_CHANNEL_HID], fake.recvs[VANILLA_CHANNEL_VID], fake.recvs[VANILLA_CHANNEL_AUD], fake.recvs[VANILLA_CHANNEL_CMD]);
        return 1;
    }

    if (fake.calls_after_close) {
        printf("FAIL (%i calls after close)\n", fake.calls_after_close);
        return 1;
    }

    printf("SUCCESS\n");
    return 0;
}

int main()
{
    if (builtin_transport()) {
        return 1;
    }

    if (rejected_plugins()) {
        return 1;
    }

    if (registered_plugin()) {
        return 1;
    }

    if (selected_transport()) {
        return 1;
    }

    if (pairing()) {
        return 1;
    }

    if (session()) {
        return 1;
    }

    return 0;
}
