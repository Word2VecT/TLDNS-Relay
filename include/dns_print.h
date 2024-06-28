#ifndef DNSR_DNS_PRINT_H
#define DNSR_DNS_PRINT_H

#include "dns_structure.h"

/**
 * @brief Print DNS message byte stream
 * @param pstring The byte stream
 * @param len The length of the byte stream
 */
void print_dns_string(const char * pstring, unsigned int len);

/**
 * @brief Print the entire DNS message
 * @param pmsg The DNS message
 */
void print_dns_message(const Dns_Msg * pmsg);

#endif //DNSR_DNS_PRINT_H