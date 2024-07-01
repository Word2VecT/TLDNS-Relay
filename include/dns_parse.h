#ifndef DNSR_DNS_PARSE_H
#define DNSR_DNS_PARSE_H

#include "dns.h"

/**
 * @brief Convert a byte stream to a DNS message structure
 * @param pmsg The DNS message structure to populate
 * @param pstring The byte stream to read from
 */
void string_to_dnsmsg(Dns_Msg * pmsg, const char * pstring);

/**
 * @brief Write a NAME field to a byte stream
 * @param pname The NAME field
 * @param pstring The start of the byte stream
 * @param offset The offset in the byte stream
 * @note After writing, the offset increases to the position after the NAME field
 */
unsigned dnsmsg_to_string(const Dns_Msg * pmsg, char * pstring);

/**
 * @brief Release memory allocated for a Resource Record
 * @param prr The Resource Record to release
 */
void destroy_dnsrr(Dns_RR * prr);

/**
 * @brief Release memory allocated for a DNS message
 * @param pmsg The DNS message to release
 */
void destroy_dnsmsg(Dns_Msg * pmsg);

/**
 * @brief Copy a Resource Record
 * @param src The Resource Record to copy
 * @return A copy of the Resource Record
 */
Dns_RR * copy_dnsrr(const Dns_RR * src);

/**
 * @brief Copy a DNS message
 * @param src The DNS message to copy
 * @return A copy of the DNS message
 */
Dns_Msg * copy_dnsmsg(const Dns_Msg * src);

#endif //DNSR_DNS_PARSE_H