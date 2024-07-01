#ifndef DNSR_DNS_SERVER_H
#define DNSR_DNS_SERVER_H

#include <uv.h>

#include "dns.h"

/**
 * @brief Initialize the DNS server
 * @param loop The libuv event loop
 */
void init_server(uv_loop_t * loop);

/**
 * @brief Send a DNS response message to local clients
 * @param addr The address of the local client
 * @param msg The DNS message to be sent
 */
void send_to_local(const struct sockaddr * addr, const Dns_Msg * msg);

#endif //DNSR_DNS_SERVER_H