#ifndef VANILLA_PLUGIN_LOADER_H
#define VANILLA_PLUGIN_LOADER_H

#include "vanilla_plugin/entry.h"

/**
 * Loads the plugin at `path` into this process and finds its entry point,
 * however the platform does it
 */
int load_plugin_module(const char *path, vanilla_plugin_entry_t *entry, void **module);

/**
 * Unloads a module whose plugin wasn't registered. Registered plugins are never
 * unloaded.
 */
void unload_plugin_module(void *module);

#endif // VANILLA_PLUGIN_LOADER_H
