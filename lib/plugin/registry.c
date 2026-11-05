#define _GNU_SOURCE

#include "registry.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "loader.h"
#include "transport/network.h"
#include "vanilla.h"

#define MAX_PLUGINS 32
#define MAX_TRANSPORTS 32

// Plugins and transports are only ever added, so pointers to them stay valid
static pthread_mutex_t registry_mutex = PTHREAD_MUTEX_INITIALIZER;
static int registry_initialized = 0;
static const vanilla_plugin_t *plugins[MAX_PLUGINS];
static size_t plugin_count = 0;
static const vanilla_transport_t *transports[MAX_TRANSPORTS];
static size_t transport_count = 0;

// Copies of the values passed to select_transport(), one per option
static const vanilla_transport_t *selected_transport = NULL;
static char **selected_values = NULL;

static void host_log(const char *message)
{
    vanilla_log("%s", message);
}

static const vanilla_host_t host = {
    .struct_size = sizeof(vanilla_host_t),
    .abi_version = VANILLA_PLUGIN_ABI_VERSION,
    .log = host_log,
};

static const vanilla_capability_t *const builtin_capabilities[] = {
    &network_transport.base,
};

static const vanilla_plugin_t builtin_plugin = {
    .struct_size = sizeof(vanilla_plugin_t),
    .abi_version = VANILLA_PLUGIN_ABI_VERSION,
    .id = "vanilla",
    .name = "vanilla",
    .version = "1",
    .capabilities = builtin_capabilities,
    .capability_count = sizeof(builtin_capabilities) / sizeof(builtin_capabilities[0]),
};

static const vanilla_transport_t *find_transport_locked(const char *id)
{
    for (size_t i = 0; i < transport_count; i++) {
        if (!strcmp(transports[i]->base.id, id)) {
            return transports[i];
        }
    }
    return NULL;
}

static int is_valid_transport(const vanilla_transport_t *t)
{
    const vanilla_capability_t *base = &t->base;
    return base->struct_size >= sizeof(vanilla_transport_t)
        && base->id && base->name
        && (base->options || !base->option_count)
        && base->open && base->close
        && t->start_sync && t->poll_sync && t->start_connect && t->poll_link && t->send && t->recv;
}

static void add_capability_locked(const vanilla_plugin_t *plugin, const vanilla_capability_t *capability)
{
    if (!capability || capability->struct_size < sizeof(vanilla_capability_t)) {
        vanilla_log("Plugin %s has an invalid capability, skipping it", plugin->id);
        return;
    }

    if (capability->type != VANILLA_CAPABILITY_TRANSPORT || capability->version != VANILLA_TRANSPORT_VERSION) {
        vanilla_log("Plugin %s has an unsupported capability (type %u, version %u), skipping it", plugin->id, (unsigned) capability->type, (unsigned) capability->version);
        return;
    }

    const vanilla_transport_t *transport = (const vanilla_transport_t *) capability;
    if (!is_valid_transport(transport)) {
        vanilla_log("Plugin %s has an invalid transport, skipping it", plugin->id);
        return;
    }

    if (find_transport_locked(capability->id)) {
        vanilla_log("Plugin %s has a transport with the same id as another (%s), skipping it", plugin->id, capability->id);
        return;
    }

    if (transport_count == MAX_TRANSPORTS) {
        vanilla_log("Too many transports, skipping %s from plugin %s", capability->id, plugin->id);
        return;
    }

    transports[transport_count++] = transport;
}

static int add_plugin_locked(const vanilla_plugin_t *plugin)
{
    if (!plugin) {
        vanilla_log("Plugin declined to load");
        return VANILLA_ERR_INVALID_ARGUMENT;
    }

    if (plugin->struct_size < sizeof(vanilla_plugin_t) || plugin->abi_version != VANILLA_PLUGIN_ABI_VERSION || !plugin->id) {
        vanilla_log("Plugin was built for an incompatible version of vanilla (ABI %u, expected %u)", (unsigned) plugin->abi_version, VANILLA_PLUGIN_ABI_VERSION);
        return VANILLA_ERR_INVALID_ARGUMENT;
    }

    for (size_t i = 0; i < plugin_count; i++) {
        if (!strcmp(plugins[i]->id, plugin->id)) {
            vanilla_log("Plugin %s is already loaded", plugin->id);
            return VANILLA_ERR_BUSY;
        }
    }

    if (plugin_count == MAX_PLUGINS) {
        vanilla_log("Too many plugins, skipping %s", plugin->id);
        return VANILLA_ERR_OUT_OF_MEMORY;
    }

    plugins[plugin_count++] = plugin;

    for (size_t i = 0; i < plugin->capability_count; i++) {
        add_capability_locked(plugin, plugin->capabilities[i]);
    }

    return VANILLA_SUCCESS;
}

static void init_registry_locked()
{
    if (!registry_initialized) {
        registry_initialized = 1;
        add_plugin_locked(&builtin_plugin);
    }
}

int register_plugin_entry(vanilla_plugin_entry_t entry)
{
    if (!entry) {
        return VANILLA_ERR_INVALID_ARGUMENT;
    }

    pthread_mutex_lock(&registry_mutex);
    init_registry_locked();
    int ret = add_plugin_locked(entry(&host));
    pthread_mutex_unlock(&registry_mutex);

    return ret;
}

int load_plugin(const char *path)
{
    vanilla_plugin_entry_t entry;
    void *module;
    int ret = load_plugin_module(path, &entry, &module);
    if (ret != VANILLA_SUCCESS) {
        return ret;
    }

    ret = register_plugin_entry(entry);
    if (ret != VANILLA_SUCCESS) {
        unload_plugin_module(module);
    }

    return ret;
}

size_t get_transport_count()
{
    pthread_mutex_lock(&registry_mutex);
    init_registry_locked();
    size_t count = transport_count;
    pthread_mutex_unlock(&registry_mutex);

    return count;
}

const vanilla_transport_t *get_transport(size_t index)
{
    pthread_mutex_lock(&registry_mutex);
    init_registry_locked();
    const vanilla_transport_t *transport = (index < transport_count) ? transports[index] : NULL;
    pthread_mutex_unlock(&registry_mutex);

    return transport;
}

static void free_values(char **values, size_t count)
{
    if (values) {
        for (size_t i = 0; i < count; i++) {
            free(values[i]);
        }
        free(values);
    }
}

// Copies the values, using an option's default where its value is missing
static char **copy_values(const vanilla_transport_t *transport, const char *const *option_values)
{
    size_t count = transport->base.option_count;
    char **copy = calloc(count ? count : 1, sizeof(char *));
    if (!copy) {
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        const char *value = option_values ? option_values[i] : NULL;
        if (!value) {
            value = transport->base.options[i].default_value;
        }
        copy[i] = strdup(value ? value : "");
        if (!copy[i]) {
            free_values(copy, i);
            return NULL;
        }
    }

    return copy;
}

int select_transport(const char *id, const char *const *option_values)
{
    if (!id) {
        return VANILLA_ERR_INVALID_ARGUMENT;
    }

    pthread_mutex_lock(&registry_mutex);
    init_registry_locked();

    int ret = VANILLA_SUCCESS;

    const vanilla_transport_t *transport = find_transport_locked(id);
    char **values = NULL;
    if (!transport) {
        vanilla_log("No transport %s", id);
        ret = VANILLA_ERR_INVALID_ARGUMENT;
    } else if (!(values = copy_values(transport, option_values))) {
        ret = VANILLA_ERR_OUT_OF_MEMORY;
    } else if (transport->base.validate) {
        size_t invalid_option = 0;
        ret = transport->base.validate((const char *const *) values, &invalid_option);
        if (ret != VANILLA_SUCCESS) {
            vanilla_log("Invalid %s for transport %s", transport->base.options[invalid_option].key, id);
        }
    }

    if (ret == VANILLA_SUCCESS) {
        if (selected_transport) {
            free_values(selected_values, selected_transport->base.option_count);
        }
        selected_transport = transport;
        selected_values = values;
    } else if (values) {
        free_values(values, transport->base.option_count);
    }

    pthread_mutex_unlock(&registry_mutex);

    return ret;
}

int open_selected_transport(const vanilla_transport_t **transport, void **ctx)
{
    pthread_mutex_lock(&registry_mutex);
    init_registry_locked();

    // Opened outside the lock, from a copy, as it may take a moment
    const vanilla_transport_t *t = selected_transport ? selected_transport : &network_transport;
    char **values = copy_values(t, selected_transport ? (const char *const *) selected_values : NULL);

    pthread_mutex_unlock(&registry_mutex);

    if (!values) {
        return VANILLA_ERR_OUT_OF_MEMORY;
    }

    *transport = t;
    int ret = t->base.open((const char *const *) values, ctx);

    free_values(values, t->base.option_count);

    return ret;
}
