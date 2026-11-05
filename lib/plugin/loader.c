#include "loader.h"

#include "vanilla.h"

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#if defined(_WIN32)
#define VANILLA_PLUGIN_LOADER_WINDOWS
#include <windows.h>
#elif defined(__SWITCH__) || (defined(__APPLE__) && TARGET_OS_IPHONE)
// These can't load code at runtime this way, so plugins can only be registered
// with vanilla_register_plugin()
#define VANILLA_PLUGIN_LOADER_NONE
#else
#define VANILLA_PLUGIN_LOADER_DLOPEN
#include <dlfcn.h>
#endif

#if defined(VANILLA_PLUGIN_LOADER_WINDOWS)

int load_plugin_module(const char *path, vanilla_plugin_entry_t *entry, void **module)
{
    HMODULE library = LoadLibraryA(path);
    if (!library) {
        vanilla_log("Failed to load plugin %s: %lu", path, GetLastError());
        return VANILLA_ERR_GENERIC;
    }

    *entry = (vanilla_plugin_entry_t) GetProcAddress(library, VANILLA_PLUGIN_ENTRY_SYMBOL);
    if (!*entry) {
        vanilla_log("Plugin %s has no %s", path, VANILLA_PLUGIN_ENTRY_SYMBOL);
        FreeLibrary(library);
        return VANILLA_ERR_GENERIC;
    }

    *module = library;
    return VANILLA_SUCCESS;
}

void unload_plugin_module(void *module)
{
    FreeLibrary((HMODULE) module);
}

#elif defined(VANILLA_PLUGIN_LOADER_DLOPEN)

int load_plugin_module(const char *path, vanilla_plugin_entry_t *entry, void **module)
{
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        vanilla_log("Failed to load plugin %s: %s", path, dlerror());
        return VANILLA_ERR_GENERIC;
    }

    *entry = (vanilla_plugin_entry_t) dlsym(library, VANILLA_PLUGIN_ENTRY_SYMBOL);
    if (!*entry) {
        vanilla_log("Plugin %s has no %s", path, VANILLA_PLUGIN_ENTRY_SYMBOL);
        dlclose(library);
        return VANILLA_ERR_GENERIC;
    }

    *module = library;
    return VANILLA_SUCCESS;
}

void unload_plugin_module(void *module)
{
    dlclose(module);
}

#else

int load_plugin_module(const char *path, vanilla_plugin_entry_t *entry, void **module)
{
    vanilla_log("Can't load plugin %s: not supported on this platform", path);
    return VANILLA_ERR_UNSUPPORTED;
}

void unload_plugin_module(void *module)
{
}

#endif
