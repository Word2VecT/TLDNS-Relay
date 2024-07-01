#include "../include/dns_parse.h"

#include <string.h>
#include <stdlib.h>

#include "../include/log.h"

#ifdef _WIN32
#include <winsock2.h>
#endif

/**
 * @brief Read a 16-bit number in big-endian format from a byte stream
 * @param pstring The start of the byte stream
 * @param offset The offset in the byte stream
 * @return The 16-bit number starting from (pstring + *offset)
 * @note After reading, the offset increases by 2
 */
static uint16_t read_uint16(const char *pstring, unsigned *offset) {
	uint16_t ret = ntohs(*(uint16_t *) (pstring + *offset));
	*offset += 2;
	return ret;
}

/**
 * @brief Read a 32-bit number in big-endian format from a byte stream
 * @param pstring The start of the byte stream
 * @param offset The offset in the byte stream
 * @return The 32-bit number starting from (pstring + *offset)
 * @note After reading, the offset increases by 4
 */
static uint32_t read_uint32(const char *pstring, unsigned *offset) {
	uint32_t ret = ntohl(*(uint32_t *) (pstring + *offset));
	*offset += 4;
	return ret;
}

/**
 * @brief Read a NAME field from a byte stream
 * @param pname The NAME field
 * @param pstring The start of the byte stream
 * @param offset The offset in the byte stream
 * @return The total length of the NAME field
 * @note After reading, the offset increases to the position after the NAME field
 */
static unsigned string_to_rrname(uint8_t *pname, const char *pstring, unsigned *offset) {
	unsigned start_offset = *offset;
	while (true) {
		if ((*(pstring + *offset) >> 6) & 0x3) { // RFC1035 4.1.4. Message compression
			unsigned new_offset = read_uint16(pstring, offset) & 0x3fff;
			return *offset - start_offset - 2 + string_to_rrname(pname, pstring, &new_offset);
		}
		if (!*(pstring + *offset)) {
			++*offset;
			*pname = 0;
			return *offset - start_offset;
		}
		int cur_length = (int) *(pstring + *offset);
		++*offset;
		memcpy(pname, pstring + *offset, cur_length);
		pname += cur_length;
		*offset += cur_length;
		*pname++ = '.';
	}
}
//static unsigned string_to_rrname(uint8_t *pname, const char *pstring, unsigned *offset) {
//	unsigned start_offset = *offset;
//	unsigned length = 0;
//
//	while (true) {
//		// 检查是否是消息压缩，根据 RFC1035 4.1.4
//		if ((*(pstring + *offset) >> 6) & 0x3) {
//			unsigned new_offset = read_uint16(pstring, offset) & 0x3fff;
//			unsigned temp_offset = *offset;
//			*offset = new_offset;
//			length += string_to_rrname(pname, pstring, offset);
//			*offset = temp_offset;
//			return length;
//		}
//
//		// 检查是否到达 NAME 字段的结束
//		if (!*(pstring + *offset)) {
//			++*offset;
//			*pname = 0;
//			return *offset - start_offset;
//		}
//
//		int cur_length = (int) *(pstring + *offset);
//		++*offset;
//		memcpy(pname, pstring + *offset, cur_length);
//		pname += cur_length;
//		*offset += cur_length;
//		*pname++ = '.';
//	}
//}

/**
 * @brief Read a Header Section from a byte stream
 * @param phead The Header Section
 * @param pstring The start of the byte stream
 * @param offset The offset in the byte stream
 * @note After reading, the offset increases to the position after the Header Section
 */
static void string_to_dnshead(Dns_Header *phead, const char *pstring, unsigned *offset) {
	phead->id = read_uint16(pstring, offset);
	uint16_t flag = read_uint16(pstring, offset);
	phead->qr = (flag >> 15) & 0x1;
	phead->opcode = (flag >> 11) & 0xF;
	phead->aa = (flag >> 10) & 0x1;
	phead->tc = (flag >> 9) & 0x1;
	phead->rd = (flag >> 8) & 0x1;
	phead->ra = (flag >> 7) & 0x1;
	phead->z = (flag >> 4) & 0x7;
	phead->rcode = flag & 0xF;
	phead->qdcount = read_uint16(pstring, offset);
	phead->ancount = read_uint16(pstring, offset);
	phead->nscount = read_uint16(pstring, offset);
	phead->arcount = read_uint16(pstring, offset);
}

/**
 * @brief Read a Question Section from a byte stream
 * @param pque The Question Section
 * @param pstring The start of the byte stream
 * @param offset The offset in the byte stream
 * @note After reading, the offset increases to the position after the Question Section; space is allocated for the NAME field
 */
static void string_to_dnsque(Dns_Que *pque, const char *pstring, unsigned *offset) {
	pque->qname = (uint8_t *) calloc(DNS_RR_NAME_MAX_SIZE, sizeof(uint8_t));
	if (!pque->qname)
		log_fatal("Memory allocation error")
	string_to_rrname(pque->qname, pstring, offset);
	pque->qtype = read_uint16(pstring, offset);
	pque->qclass = read_uint16(pstring, offset);
}

/**
 * @brief Read a Resource Record from a byte stream
 * @param prr The Resource Record
 * @param pstring The start of the byte stream
 * @param offset The offset in the byte stream
 * @note After reading, the offset increases to the position after the Resource Record; space is allocated for the NAME and RDATA fields
 */
static void string_to_dnsrr(Dns_RR *prr, const char *pstring, unsigned *offset) {
	prr->name = (uint8_t *) calloc(DNS_RR_NAME_MAX_SIZE, sizeof(uint8_t));
	if (!prr->name)
		log_fatal("Memory allocation error")
	string_to_rrname(prr->name, pstring, offset);
	prr->type = read_uint16(pstring, offset);
	prr->class = read_uint16(pstring, offset);
	prr->ttl = read_uint32(pstring, offset);
	prr->rdlength = read_uint16(pstring, offset);
	if (prr->type == DNS_TYPE_CNAME || prr->type == DNS_TYPE_NS) // RDATA for CNAME and NS is a domain name
	{
		uint8_t *temp = (uint8_t *) calloc(DNS_RR_NAME_MAX_SIZE, sizeof(uint8_t));
		if (!temp)
			log_fatal("Memory allocation error")
		prr->rdlength = string_to_rrname(temp, pstring, offset);
		prr->rdata = (uint8_t *) calloc(prr->rdlength, sizeof(uint8_t));
		if (!prr->rdata)
			log_fatal("Memory allocation error")
		memcpy(prr->rdata, temp, prr->rdlength);
		free(temp);
	} else if (prr->type == DNS_TYPE_MX) // RFC1035 3.3.9. MX RDATA format
	{
		uint8_t *temp = (uint8_t *) calloc(DNS_RR_NAME_MAX_SIZE, sizeof(uint8_t));
		if (!temp)
			log_fatal("Memory allocation error")
		unsigned temp_offset = *offset + 2;
		prr->rdlength = string_to_rrname(temp, pstring, &temp_offset);
		prr->rdata = (uint8_t *) calloc(prr->rdlength + 2, sizeof(uint8_t));
		if (!prr->rdata)
			log_fatal("Memory allocation error")
		memcpy(prr->rdata, pstring + *offset, 2);
		memcpy(prr->rdata + 2, temp, prr->rdlength);
		prr->rdlength += 2;
		*offset = temp_offset;
		free(temp);
	} else if (prr->type == DNS_TYPE_SOA) // RFC1035 3.3.13. SOA RDATA format
	{
		uint8_t *temp = (uint8_t *) calloc(DNS_RR_NAME_MAX_SIZE, sizeof(uint8_t));
		if (!temp) {
			log_fatal("Memory allocation error")
			return;
		}
		prr->rdlength = string_to_rrname(temp, pstring, offset);
		prr->rdlength += string_to_rrname(temp + prr->rdlength, pstring, offset);
		prr->rdata = (uint8_t *) calloc(prr->rdlength + 20, sizeof(uint8_t));
		if (!prr->rdata)
			log_fatal("Memory allocation error")
		memcpy(prr->rdata, temp, prr->rdlength);
		memcpy(prr->rdata + prr->rdlength, pstring + *offset, 20);
		*offset += 20;
		prr->rdlength += 20;
		free(temp);
	} else {
		prr->rdata = (uint8_t *) calloc(prr->rdlength, sizeof(uint8_t));
		if (!prr->rdata)
			log_fatal("Memory allocation error")
		memcpy(prr->rdata, pstring + *offset, prr->rdlength);
		*offset += prr->rdlength;
	}
}

/**
 * @brief Convert a byte stream to a DNS message structure
 * @param pmsg The DNS message structure to populate
 * @param pstring The byte stream to read from
 */
void string_to_dnsmsg(Dns_Msg *pmsg, const char *pstring) {
	unsigned offset = 0;
	pmsg->header = (Dns_Header *) calloc(1, sizeof(Dns_Header));
	if (!pmsg->header)
		log_fatal("Memory allocation error")
	string_to_dnshead(pmsg->header, pstring, &offset);
	Dns_Que *que_tail = NULL; // Tail pointer for the Question Section linked list
	for (int i = 0; i < pmsg->header->qdcount; ++i) {
		Dns_Que *temp = (Dns_Que *) calloc(1, sizeof(Dns_Que));
		if (!temp)
			log_fatal("Memory allocation error")
		if (!que_tail) // First node in the linked list
			pmsg->que = que_tail = temp;
		else {
			que_tail->next = temp;
			que_tail = temp;
		}
		string_to_dnsque(que_tail, pstring, &offset);
	}
	int tot = pmsg->header->ancount + pmsg->header->nscount + pmsg->header->arcount;
	Dns_RR *rr_tail = NULL; // Tail pointer for the Resource Record linked list
	for (int i = 0; i < tot; ++i) {
		Dns_RR *temp = (Dns_RR *) calloc(1, sizeof(Dns_RR));
		if (!temp)
			log_fatal("Memory allocation error")
		if (!rr_tail) // First node in the linked list
			pmsg->rr = rr_tail = temp;
		else {
			rr_tail->next = temp;
			rr_tail = temp;
		}
		string_to_dnsrr(rr_tail, pstring, &offset);
	}
}

/**
 * @brief Write a 16-bit number in little-endian format to a byte stream
 * @param pstring The start of the byte stream
 * @param offset The offset in the byte stream
 * @param num The number to write
 * @note After writing, the offset increases by 2
 */
static void write_uint16(const char *pstring, unsigned *offset, uint16_t num) {
	*(uint16_t *) (pstring + *offset) = htons(num);
	*offset += 2;
}

/**
 * @brief Write a 32-bit number in little-endian format to a byte stream
 * @param pstring The start of the byte stream
 * @param offset The offset in the byte stream
 * @param num The number to write
 * @note After writing, the offset increases by 4
 */
static void write_uint32(const char *pstring, unsigned *offset, uint32_t num) {
	*(uint32_t *) (pstring + *offset) = htonl(num);
	*offset += 4;
}

/**
 * @brief Write a NAME field to a byte stream
 * @param pname The NAME field
 * @param pstring The start of the byte stream
 * @param offset The offset in the byte stream
 * @note After writing, the offset increases to the position after the NAME field
 */
static void rrname_to_string(const uint8_t *pname, char *pstring, unsigned *offset) {
	while (true) {
		uint8_t *loc = (uint8_t *) strchr((char *) pname, '.');
		if (loc == NULL) break;
		long cur_length = loc - pname;
		pstring[(*offset)++] = (char) cur_length;
		memcpy(pstring + *offset, pname, cur_length);
		pname += cur_length + 1;
		*offset += cur_length;
	}
	pstring[(*offset)++] = 0;
}

/**
 * @brief Write a Header Section to a byte stream
 * @param phead The Header Section
 * @param pstring The start of the byte stream
 * @param offset The offset in the byte stream
 * @note After writing, the offset increases to the position after the Header Section
 */
static void dnshead_to_string(const Dns_Header *phead, char *pstring, unsigned *offset) {
	write_uint16(pstring, offset, phead->id);
	uint16_t flag = 0;
	flag |= phead->qr << 15;
	flag |= phead->opcode << 11;
	flag |= phead->aa << 10;
	flag |= phead->tc << 9;
	flag |= phead->rd << 8;
	flag |= phead->ra << 7;
	flag |= phead->z << 4;
	flag |= phead->rcode;
	write_uint16(pstring, offset, flag);
	write_uint16(pstring, offset, phead->qdcount);
	write_uint16(pstring, offset, phead->ancount);
	write_uint16(pstring, offset, phead->nscount);
	write_uint16(pstring, offset, phead->arcount);
}

/**
 * @brief Write a Question Section to a byte stream
 * @param pque The Question Section
 * @param pstring The start of the byte stream
 * @param offset The offset in the byte stream
 * @note After writing, the offset increases to the position after the Question Section
 */
static void dnsque_to_string(const Dns_Que *pque, char *pstring, unsigned *offset) {
	rrname_to_string(pque->qname, pstring, offset);
	write_uint16(pstring, offset, pque->qtype);
	write_uint16(pstring, offset, pque->qclass);
}

/**
 * @brief Write a Resource Record to a byte stream
 * @param prr The Resource Record
 * @param pstring The start of the byte stream
 * @param offset The offset in the byte stream
 * @note After writing, the offset increases to the position after the Resource Record
 */
static void dnsrr_to_string(const Dns_RR *prr, char *pstring, unsigned *offset) {
	rrname_to_string(prr->name, pstring, offset);
	write_uint16(pstring, offset, prr->type);
	write_uint16(pstring, offset, prr->class);
	write_uint32(pstring, offset, prr->ttl);
	write_uint16(pstring, offset, prr->rdlength);
	if (prr->type == DNS_TYPE_CNAME || prr->type == DNS_TYPE_NS)
		rrname_to_string(prr->rdata, pstring, offset);
	else if (prr->type == DNS_TYPE_MX) {
		unsigned temp_offset = *offset + 2;
		rrname_to_string(prr->rdata + 2, pstring, &temp_offset);
		memcpy(pstring + *offset, prr->rdata, 2);
		*offset = temp_offset;
	} else if (prr->type == DNS_TYPE_SOA) {
		rrname_to_string(prr->rdata, pstring, offset);
		rrname_to_string(prr->rdata + strlen((const char *) prr->rdata) + 1, pstring, offset);
		memcpy(pstring + *offset, prr->rdata + prr->rdlength - 20, 20);
		*offset += 20;
	} else {
		memcpy(pstring + *offset, prr->rdata, prr->rdlength);
		*offset += prr->rdlength;
	}
}

/**
 * @brief Convert a DNS message structure to a byte stream
 * @param pmsg The DNS message structure to convert
 * @param pstring The byte stream to write to
 * @return The total length of the byte stream
 */
unsigned dnsmsg_to_string(const Dns_Msg *pmsg, char *pstring) {
	unsigned offset = 0;
	dnshead_to_string(pmsg->header, pstring, &offset);
	Dns_Que *pque = pmsg->que;
	for (int i = 0; i < pmsg->header->qdcount; ++i) {
		dnsque_to_string(pque, pstring, &offset);
		pque = pque->next;
	}
	int tot = pmsg->header->ancount + pmsg->header->nscount + pmsg->header->arcount;
	Dns_RR *prr = pmsg->rr;
	for (int i = 0; i < tot; ++i) {
		dnsrr_to_string(prr, pstring, &offset);
		prr = prr->next;
	}
	return offset;
}

/**
 * @brief Release memory allocated for a Resource Record
 * @param prr The Resource Record to release
 */
void destroy_dnsrr(Dns_RR *prr) {
	Dns_RR *now = prr;
	while (now != NULL) {
		Dns_RR *next = now->next;
		free(now->name);
		free(now->rdata);
		free(now);
		now = next;
	}
}

/**
 * @brief Release memory allocated for a DNS message
 * @param pmsg The DNS message to release
 */
void destroy_dnsmsg(Dns_Msg *pmsg) {
	log_debug("Releasing DNS message memory ID: 0x%04x", pmsg->header->id)
	free(pmsg->header);
	Dns_Que *now = pmsg->que;
	while (now != NULL) {
		Dns_Que *next = now->next;
		free(now->qname);
		free(now);
		now = next;
	}
	destroy_dnsrr(pmsg->rr);
	free(pmsg);
}

/**
 * @brief Copy a Resource Record
 * @param src The Resource Record to copy
 * @return A copy of the Resource Record
 */
Dns_RR *copy_dnsrr(const Dns_RR *src) {
	if (src == NULL) return NULL;
	// Copy the head node of the linked list
	Dns_RR *new_rr = (Dns_RR *) calloc(1, sizeof(Dns_RR)), *rr = new_rr;
	if (!new_rr) {
		log_fatal("Memory allocation error")
		return NULL;
	}
	const Dns_RR *old_rr = src;
	memcpy(new_rr, old_rr, sizeof(Dns_RR));
	new_rr->name = (uint8_t *) calloc(DNS_RR_NAME_MAX_SIZE, sizeof(uint8_t));
	if (!new_rr->name)
		log_fatal("Memory allocation error")
	memcpy(new_rr->name, old_rr->name, DNS_RR_NAME_MAX_SIZE);
	new_rr->rdata = (uint8_t *) calloc(DNS_RR_NAME_MAX_SIZE, sizeof(uint8_t));
	if (!new_rr->rdata)
		log_fatal("Memory allocation error")
	memcpy(new_rr->rdata, old_rr->rdata, DNS_RR_NAME_MAX_SIZE);
	// Copy the remaining nodes of the linked list
	while (old_rr->next) {
		new_rr->next = (Dns_RR *) calloc(1, sizeof(Dns_RR));
		if (!new_rr->next)
			log_fatal("Memory allocation error")
		old_rr = old_rr->next;
		new_rr = new_rr->next;
		memcpy(new_rr, old_rr, sizeof(Dns_RR));
		new_rr->name = (uint8_t *) calloc(DNS_RR_NAME_MAX_SIZE, sizeof(uint8_t));
		if (!new_rr->name)
			log_fatal("Memory allocation error")
		memcpy(new_rr->name, old_rr->name, DNS_RR_NAME_MAX_SIZE);
		new_rr->rdata = (uint8_t *) calloc(DNS_RR_NAME_MAX_SIZE, sizeof(uint8_t));
		if (!new_rr->rdata)
			log_fatal("Memory allocation error")
		memcpy(new_rr->rdata, old_rr->rdata, DNS_RR_NAME_MAX_SIZE);
	}
	return rr;
}

/**
 * @brief Copy a DNS message
 * @param src The DNS message to copy
 * @return A copy of the DNS message
 */
Dns_Msg *copy_dnsmsg(const Dns_Msg *src) {
	if (src == NULL) return NULL;
	Dns_Msg *new_msg = (Dns_Msg *) calloc(1, sizeof(Dns_Msg));
	if (!new_msg) {
		log_fatal("Memory allocation error")
		return NULL;
	}
	new_msg->header = (Dns_Header *) calloc(1, sizeof(Dns_Header));
	if (!new_msg->header)
		log_fatal("Memory allocation error")
	memcpy(new_msg->header, src->header, sizeof(Dns_Header));

	// Copy the head node of the linked list
	new_msg->que = (Dns_Que *) calloc(1, sizeof(Dns_Que));
	if (!new_msg->que)
		log_fatal("Memory allocation error")
	Dns_Que *que = new_msg->que, *old_que = src->que;
	memcpy(que, old_que, sizeof(Dns_Que));
	que->qname = (uint8_t *) calloc(DNS_RR_NAME_MAX_SIZE, sizeof(uint8_t));
	if (!que->qname)
		log_fatal("Memory allocation error")
	memcpy(que->qname, old_que->qname, DNS_RR_NAME_MAX_SIZE);
	// Copy the remaining nodes of the linked list
	while (old_que->next) {
		que->next = (Dns_Que *) calloc(1, sizeof(Dns_Que));
		if (!que->next)
			log_fatal("Memory allocation error")
		old_que = old_que->next;
		que = que->next;
		memcpy(que, old_que, sizeof(Dns_Que));
		que->qname = (uint8_t *) calloc(DNS_RR_NAME_MAX_SIZE, sizeof(uint8_t));
		if (!que->qname)
			log_fatal("Memory allocation error")
		memcpy(que->qname, old_que->qname, DNS_RR_NAME_MAX_SIZE);
	}

	new_msg->rr = copy_dnsrr(src->rr);
	return new_msg;
}