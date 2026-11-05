#ifndef VANILLA_PLUGIN_ENTRY_H
#define VANILLA_PLUGIN_ENTRY_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "capability.h"

/**
 * Covers vanilla_plugin_t, vanilla_host_t and vanilla_capability_t. A plugin
 * built for another version is rejected.
 */
#define VANILLA_PLUGIN_ABI_VERSION 1

/**
 * What a plugin provides
 */
typedef struct vanilla_plugin {
    uint32_t struct_size; // sizeof(vanilla_plugin_t) the plugin was built with
    uint32_t abi_version; // VANILLA_PLUGIN_ABI_VERSION the plugin was built with
    const char *id;       // Stable, e.g. "example-transports"
    const char *name;     // Shown to the user
    const char *version;  // Shown to the user

    // Each points to a full capability struct, e.g. a vanilla_transport_t.
    // Capabilities of a type or major version vanilla doesn't support are
    // skipped.
    const vanilla_capability_t *const *capabilities;
    size_t capability_count;
} vanilla_plugin_t;

/**
 * What vanilla gives a plugin
 */
typedef struct vanilla_host {
    uint32_t struct_size; // sizeof(vanilla_host_t) vanilla was built with
    uint32_t abi_version; // VANILLA_PLUGIN_ABI_VERSION vanilla was built with

    // Logs one line, without needing a trailing newline. May be called from
    // any thread.
    void (*log)(const char *message);
} vanilla_host_t;

/**
 * The one function a plugin provides, exported from shared libraries under
 * VANILLA_PLUGIN_ENTRY_SYMBOL. Returns NULL to decline loading. The plugin, and
 * everything it points to, must stay valid as long as the plugin is loaded.
 */
typedef const vanilla_plugin_t *(*vanilla_plugin_entry_t)(const vanilla_host_t *host);
#define VANILLA_PLUGIN_ENTRY_SYMBOL "vanilla_plugin_entry"

#if defined(__cplusplus)
}
#endif

#endif // VANILLA_PLUGIN_ENTRY_H
