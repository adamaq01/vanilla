#ifndef VANILLA_PLUGIN_REGISTRY_H
#define VANILLA_PLUGIN_REGISTRY_H

#include <stddef.h>

#include "vanilla_plugin/entry.h"
#include "vanilla_plugin/transport.h"

int register_plugin_entry(vanilla_plugin_entry_t entry);
int load_plugin(const char *path);

size_t get_transport_count();
const vanilla_transport_t *get_transport(size_t index);
int select_transport(const char *id, const char *const *option_values);

/**
 * Opens the transport selected with select_transport(), or vanilla-pipe on
 * this machine if none was
 */
int open_selected_transport(const vanilla_transport_t **transport, void **ctx);

#endif // VANILLA_PLUGIN_REGISTRY_H
