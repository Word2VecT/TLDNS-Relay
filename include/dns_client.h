#ifndef DNSR_DNS_CLIENT_H
#define DNSR_DNS_CLIENT_H

#include <uv.h>

#include "dns_structure.h"

/**
 * @brief Initialize the DNS client
 * @param loop The libuv event loop
 */
void init_client(uv_loop_t * loop);

/**
 * @brief Send a DNS query message to the remote server
 * @param msg The DNS message to be sent
 */
void send_to_remote(const Dns_Msg * msg);

#endif //DNSR_DNS_CLIENT_H