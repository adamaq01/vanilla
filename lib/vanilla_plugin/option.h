#ifndef VANILLA_PLUGIN_OPTION_H
#define VANILLA_PLUGIN_OPTION_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>

typedef enum {
    VANILLA_OPTION_STRING,
    VANILLA_OPTION_INT,
    VANILLA_OPTION_BOOL,   // "0" or "1"
    VANILLA_OPTION_CHOICE, // One of a list of values
} vanilla_option_type_t;

/**
 * A setting a capability declares, which the frontend shows and stores
 */
typedef struct {
    const char *key;            // Stable identifier, [a-z0-9_]+
    const char *label;          // Shown to the user
    uint32_t type;              // vanilla_option_type_t
    const char *default_value;  // As a string

    // VANILLA_OPTION_CHOICE: NULL-terminated fixed values, or NULL for the
    // capability to list them at runtime
    const char *const *choices;
} vanilla_option_t;

/**
 * Receives one choice from vanilla_capability_t::list_choices. The strings only
 * need to stay valid during the call.
 */
typedef void (*vanilla_choice_cb_t)(void *user, const char *value, const char *label);

#if defined(__cplusplus)
}
#endif

#endif // VANILLA_PLUGIN_OPTION_H
