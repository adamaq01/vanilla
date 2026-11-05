#ifndef VANILLA_TRANSPORT_NETWORK_H
#define VANILLA_TRANSPORT_NETWORK_H

#include <stdint.h>

#include "vanilla_plugin/transport.h"

/**
 * Reaches the console through vanilla-pipe, locally or on another machine,
 * over UDP sockets
 */
extern const vanilla_transport_t network_transport;

// Indices into network_transport's options
#define NETWORK_OPTION_SERVER 0    // "local", or the IPv4 address of a remote vanilla-pipe
#define NETWORK_OPTION_INTERFACE 1 // Wireless interface the local vanilla-pipe uses
#define NETWORK_OPTION_COUNT 2

/**
 * Formats a server address as passed to vanilla_start() into the server
 * option's value
 */
void network_format_server(uint32_t server_address, char *buf, size_t size);

/**
 * Asks vanilla-pipe to install or uninstall its polkit rules. This manages
 * vanilla-pipe itself, so it isn't part of the transport interface.
 */
int network_install_polkit(uint32_t server_address, int install);

#endif // VANILLA_TRANSPORT_NETWORK_H
