#ifndef VANILLA_PLUGIN_CAPABILITY_H
#define VANILLA_PLUGIN_CAPABILITY_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "option.h"

typedef enum {
    VANILLA_CAPABILITY_TRANSPORT = 1, // vanilla_transport_t
} vanilla_capability_type_t;

/**
 * Every capability struct starts with this base, so any capability can be
 * identified, configured and opened the same way, including types that aren't
 * known (those are skipped)
 */
typedef struct vanilla_capability {
    uint32_t struct_size; // Size of the whole capability struct, e.g. sizeof(vanilla_transport_t)
    uint32_t type;        // vanilla_capability_type_t
    uint32_t version;     // Major version of this type's interface, e.g. VANILLA_TRANSPORT_VERSION
    const char *id;       // Stable, stored in the frontend's config, e.g. "network"
    const char *name;     // Shown to the user

    const vanilla_option_t *options;
    size_t option_count;

    /**
     * Optional (NULL if unused): calls `add` once per choice of options[option]
     * when its `choices` is NULL, e.g. the devices currently plugged in.
     * Returns the number of choices or an error.
     */
    int (*list_choices)(size_t option, vanilla_choice_cb_t add, void *user);

    /**
     * Optional (NULL if unused): VANILLA_SUCCESS if the values can be used,
     * otherwise an error with *invalid_option set to the index of the first
     * invalid one
     */
    int (*validate)(const char *const *option_values, size_t *invalid_option);

    // option_values[i] is the value of options[i], as a string, never NULL
    int (*open)(const char *const *option_values, void **ctx);
    void (*close)(void *ctx);
} vanilla_capability_t;

#if defined(__cplusplus)
}
#endif

#endif // VANILLA_PLUGIN_CAPABILITY_H
