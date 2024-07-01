#include "../include/dns_print.h"

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "../include/log.h"

/**
 * @brief Print DNS message byte stream
 * @param pstring The byte stream
 * @param len The length of the byte stream
 */
void print_dns_string(const char *pstring, unsigned int len) {
	if (!(LOG_MASK & 1)) return;
	log_debug("DNS message byte stream:")
	for (unsigned int i = 0; i < len; i++) {
		if (i % 16 == 0) {
			if (i) fprintf(log_file, "\n");
			fprintf(log_file, "%04x ", i);
		}
		fprintf(log_file, "%02hhx ", pstring[i]);
	}
	fprintf(log_file, "\n");
}

/**
 * @brief Print the rdata field of an A type RR
 * @param rdata The rdata field
 */
static void print_rr_A(const uint8_t *rdata) {
	fprintf(log_file, "%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3]);
}

/**
 * @brief Print the rdata field of an AAAA type RR
 * @param rdata The rdata field
 */
static void print_rr_AAAA(const uint8_t *rdata) {
	for (int i = 0; i < 16; i += 2) {
		if (i) fprintf(log_file, ":");
		fprintf(log_file, "%x", (rdata[i] << 8) + rdata[i + 1]);
	}
}

/**
 * @brief Print the rdata field of a CNAME type RR
 * @param rdata The rdata field
 */
static void print_rr_CNAME(const uint8_t *rdata) {
	fprintf(log_file, "%s", rdata);
}

/**
 * @brief Print the rdata field of an SOA type RR
 * @param rdlength The rdlength field
 * @param rdata The rdata field
 */
static void print_rr_SOA(uint16_t rdlength, const uint8_t *rdata) {
	print_rr_CNAME(rdata);
	fprintf(log_file, " ");
	print_rr_CNAME(rdata + strlen((char *) rdata) + 1);
	fprintf(log_file, " ");
	fprintf(log_file, "%" PRIu32 " ", ntohl(*(uint32_t *) (rdata + rdlength - 20)));
	fprintf(log_file, "%" PRIu32 " ", ntohl(*(uint32_t *) (rdata + rdlength - 16)));
	fprintf(log_file, "%" PRIu32 " ", ntohl(*(uint32_t *) (rdata + rdlength - 12)));
	fprintf(log_file, "%" PRIu32 " ", ntohl(*(uint32_t *) (rdata + rdlength - 8)));
	fprintf(log_file, "%" PRIu32, ntohl(*(uint32_t *) (rdata + rdlength - 4)));
}

/**
 * @brief Print the rdata field of an MX type RR
 * @param rdata The rdata field
 */
static void print_rr_MX(const uint8_t *rdata) {
	fprintf(log_file, "%" PRIu32 " ", ntohl(*(uint32_t *) rdata));
	print_rr_CNAME(rdata + 2);
}

/**
 * @brief Print the Header Section
 * @param phead The Header Section
 */
static void print_dns_header(const Dns_Header *phead) {
	fprintf(log_file, "ID = 0x%04" PRIx16 "\n", phead->id);
	fprintf(log_file, "QR = %" PRIu8 "\n", phead->qr);
	fprintf(log_file, "OPCODE = %" PRIu8 "\n", phead->opcode);
	fprintf(log_file, "AA = %" PRIu8 "\n", phead->aa);
	fprintf(log_file, "TC = %" PRIu8 "\n", phead->tc);
	fprintf(log_file, "RD = %" PRIu8 "\n", phead->rd);
	fprintf(log_file, "RA = %" PRIu8 "\n", phead->ra);
	fprintf(log_file, "RCODE = %" PRIu16 "\n", phead->rcode);
	fprintf(log_file, "QDCOUNT = %" PRIu16 "\n", phead->qdcount);
	fprintf(log_file, "ANCOUNT = %" PRIu16 "\n", phead->ancount);
	fprintf(log_file, "NSCOUNT = %" PRIu16 "\n", phead->nscount);
	fprintf(log_file, "ARCOUNT = %" PRIu16 "\n", phead->arcount);
}

/**
 * @brief Print the Question Section
 * @param pque The Question Section
 */
static void print_dns_question(const Dns_Que *pque) {
	fprintf(log_file, "QNAME = %s\n", pque->qname);
	fprintf(log_file, "QTYPE = %" PRIu16 "\n", pque->qtype);
	fprintf(log_file, "QCLASS = %" PRIu16 "\n", pque->qclass);
}

/**
 * @brief Print the Resource Record
 * @param prr The Resource Record
 */
static void print_dns_rr(const Dns_RR *prr) {
	fprintf(log_file, "NAME = %s\n", prr->name);
	fprintf(log_file, "TYPE = %" PRIu16 "\n", prr->type);
	fprintf(log_file, "CLASS = %" PRIu16 "\n", prr->class);
	fprintf(log_file, "TTL = %" PRIu32 "\n", prr->ttl);
	fprintf(log_file, "RDLENGTH = %" PRIu16 "\n", prr->rdlength);
	fprintf(log_file, "RDATA = ");
	if (prr->type == DNS_TYPE_A)
		print_rr_A(prr->rdata);
	else if (prr->type == DNS_TYPE_CNAME || prr->type == DNS_TYPE_NS)
		print_rr_CNAME(prr->rdata);
	else if (prr->type == DNS_TYPE_MX)
		print_rr_MX(prr->rdata);
	else if (prr->type == DNS_TYPE_AAAA)
		print_rr_AAAA(prr->rdata);
	else if (prr->type == DNS_TYPE_SOA)
		print_rr_SOA(prr->rdlength, prr->rdata);
	else
		for (int i = 0; i < prr->rdlength; ++i)
			fprintf(log_file, "%" PRIu8, *(prr->rdata + i));
	fprintf(log_file, "\n");
}

/**
 * @brief Print the entire DNS message
 * @param pmsg The DNS message
 */
void print_dns_message(const Dns_Msg *pmsg) {
	if (!(LOG_MASK & 1)) return;
	log_debug("DNS message content:")
	fprintf(log_file, "=======Header==========\n");
	print_dns_header(pmsg->header);
	fprintf(log_file, "\n");
	fprintf(log_file, "=======Question========\n");
	for (Dns_Que *pque = pmsg->que; pque; pque = pque->next) {
		print_dns_question(pque);
		fprintf(log_file, "\n");
	}
	Dns_RR *prr = pmsg->rr;
	fprintf(log_file, "=======Answer==========\n");
	for (int i = 0; i < pmsg->header->ancount; ++i, prr = prr->next) {
		print_dns_rr(prr);
		fprintf(log_file, "\n");
	}
	fprintf(log_file, "=======Authority=======\n");
	for (int i = 0; i < pmsg->header->nscount; ++i, prr = prr->next) {
		print_dns_rr(prr);
		fprintf(log_file, "\n");
	}
	fprintf(log_file, "=======Additional======\n");
	for (int i = 0; i < pmsg->header->arcount; ++i, prr = prr->next) {
		print_dns_rr(prr);
		fprintf(log_file, "\n");
	}
}