#include "../include/cache.h"

#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "../include/util.h"
#include "../include/dns_conversion.h"

/**
 * @brief Compute the hash of a string using the BKDR hash algorithm.
 * @param str The input string.
 * @return The computed hash value.
 */
static unsigned int BKDRHash(const uint8_t *str) {
	unsigned int seed = 131;
	unsigned int hash = 0;
	while (*str) {
		hash = hash * seed + (*str++);
	}
	return (hash & 0x7FFFFFFF);
}

/**
 * @brief Get the smallest TTL (Time-To-Live) value in a list of Resource Records (RRs).
 * @param prr The head node of the RR linked list.
 * @return The minimum TTL value.
 */
static uint32_t get_min_ttl(const Dns_RR *prr) {
	if (prr == NULL) {
		return 0;
	}
	uint32_t ttl = prr->ttl;
	prr = prr->next;
	while (prr != NULL) {
		if (prr->ttl < ttl)
			ttl = prr->ttl;
		prr = prr->next;
	}
	return ttl;
}

/**
 * @brief Insert a DNS message into the cache.
 * @param cache The cache where the message will be inserted.
 * @param msg The DNS message to be inserted.
 */
static void cache_insert(Cache *cache, const Dns_Msg *msg) {
	if (msg->rr == NULL) return;
	log_debug("Inserting into cache")

	Rbtree_Value *value = (Rbtree_Value *) calloc(1, sizeof(Rbtree_Value));
	if (!value) {
		log_fatal("Memory allocation error")
		return;
	}
	value->rr = copy_dnsrr(msg->rr);
	value->ancount = msg->header->ancount;
	value->nscount = msg->header->nscount;
	value->arcount = msg->header->arcount;
	value->type = msg->que->qtype;
	Dns_RR_LinkList *new_list_node = new_linklist();
	new_list_node->value = value;
	new_list_node->expire_time = time(NULL) + get_min_ttl(value->rr);
	if (cache->size == CACHE_SIZE) {
		cache->head->delete_next(cache->head); // Remove the least recently accessed element
		--cache->size;
	}
	log_debug("Inserting into cache")
	cache->tail->insert(cache->tail, new_list_node);
	cache->tail = cache->tail->next;
	++cache->size;

	value = (Rbtree_Value *) calloc(1, sizeof(Rbtree_Value));
	if (!value) {
		log_fatal("Memory allocation error")
		return;
	}

	value->rr = copy_dnsrr(msg->rr);
	value->ancount = msg->header->ancount;
	value->nscount = msg->header->nscount;
	value->arcount = msg->header->arcount;
	value->type = msg->que->qtype;
	new_list_node = new_linklist();
	new_list_node->value = value;
	new_list_node->expire_time = time(NULL) + get_min_ttl(value->rr);
	cache->tree->insert(cache->tree, BKDRHash(value->rr->name), new_list_node); // Insert into red-black tree
}

/**
 * @brief Query the cache for a DNS question.
 * @param cache The cache to query.
 * @param que The DNS question.
 * @return The value found in the cache or NULL if not found.
 */
static Rbtree_Value *cache_query(Cache *cache, const Dns_Que *que) {
	log_info("Querying cache")
	Dns_RR_LinkList *list = cache->head->query_next(cache->head, que->qname, que->qtype);
	if (list != NULL) {
		log_info("Cache hit")
		Dns_RR_LinkList *temp = list->next;
		if (temp != cache->tail) {
			list->next = list->next->next;
			cache->tail->insert(cache->tail, temp);
			cache->tail = cache->tail->next;
		}

		Rbtree_Value *value = (Rbtree_Value *) calloc(1, sizeof(Rbtree_Value));
		if (!value) {
			log_fatal("Memory allocation error")
			return NULL;
		}
		memcpy(value, temp->value, sizeof(Rbtree_Value));
		value->rr = copy_dnsrr(temp->value->rr);
		return value;
	}

	log_info("Cache miss")
	list = cache->tree->query(cache->tree, BKDRHash(que->qname));
	while (list != NULL) {
		if (strcmp((char *)list->value->rr->name, (char *)que->qname) == 0 &&
		    (list->value->type == 255 || list->value->type == que->qtype)) {
			log_info("Red-black tree hit")
			Rbtree_Value *value = (Rbtree_Value *) calloc(1, sizeof(Rbtree_Value));
			if (!value) {
				log_fatal("Memory allocation error")
				return NULL;
			}
			memcpy(value, list->value, sizeof(Rbtree_Value));
			value->rr = copy_dnsrr(list->value->rr);
			Dns_RR_LinkList *new_list_node = new_linklist();
			new_list_node->value = value;
			new_list_node->expire_time = list->expire_time;
			if (cache->size == CACHE_SIZE) {
				cache->head->delete_next(cache->head); // Remove the least recently accessed element
				--cache->size;
			}
			cache->tail->insert(cache->tail, new_list_node);
			cache->tail = cache->tail->next;
			++cache->size;

			value = (Rbtree_Value *) calloc(1, sizeof(Rbtree_Value));
			if (!value) {
				log_fatal("Memory allocation error")
				return NULL;
			}
			memcpy(value, list->value, sizeof(Rbtree_Value));
			value->rr = copy_dnsrr(list->value->rr);
			return value;
		}
		list = list->next;
	}
	log_info("Red-black tree miss")
	return NULL;
}

/**
 * @brief Create a new cache and initialize it with data from the hosts file.
 * @param hosts_file The file containing hosts data.
 * @return The newly created cache.
 */
Cache *new_cache(FILE *hosts_file) {
	log_info("Initializing cache")
	Cache *cache = (Cache *) malloc(sizeof(Cache));
	if (!cache) {
		log_fatal("Memory allocation error")
		return NULL;
	}
	Rbtree *tree = new_rbtree();
	if (hosts_file != NULL) {
		char ip[DNS_RR_NAME_MAX_SIZE], domain[DNS_RR_NAME_MAX_SIZE];
		while (fscanf(hosts_file, "%s %s", ip, domain) != EOF) { // Read domain-IP from file
			Dns_RR *rr = (Dns_RR *) calloc(1, sizeof(Dns_RR));
			if (!rr) {
				log_fatal("Memory allocation error")
				return NULL;
			}
			rr->name = (uint8_t *) calloc(DNS_RR_NAME_MAX_SIZE, sizeof(uint8_t));
			if (!rr->name)
				log_fatal("Memory allocation error")
			memcpy(rr->name, domain, strlen(domain) + 1);
			rr->name[strlen(domain) + 1] = 0;
			rr->name[strlen(domain)] = '.';
			rr->class = DNS_CLASS_IN;
			rr->ttl = -1; // Permanent
			if (strchr(ip, '.') != NULL) { // IPv4
				if (strcmp(ip, "0.0.0.0") == 0)
					rr->type = 255;
				else
					rr->type = DNS_TYPE_A;
				rr->rdlength = 4;
				rr->rdata = (uint8_t *) calloc(4, sizeof(uint8_t));
				if (!rr->rdata) {
					log_fatal("Memory allocation error")
					exit(1);
				}
				uv_inet_pton(AF_INET, ip, rr->rdata);
			} else { // IPv6
				rr->type = DNS_TYPE_AAAA;
				rr->rdlength = 16;
				rr->rdata = (uint8_t *) calloc(16, sizeof(uint8_t));
				if (!rr->rdata)
					log_fatal("Memory allocation error")
				uv_inet_pton(AF_INET6, ip, rr->rdata);
			}
			Rbtree_Value *value = (Rbtree_Value *) calloc(1, sizeof(Rbtree_Value));
			if (!value) {
				log_fatal("Memory allocation error")
				return NULL;
			}
			value->rr = rr;
			value->ancount = 1;
			value->type = rr->type;
			Dns_RR_LinkList *list = new_linklist();
			list->value = value;
			list->expire_time = -1;
			tree->insert(tree, BKDRHash(rr->name), list);
		}
	}

	cache->tree = tree;
	cache->head = cache->tail = new_linklist();
	cache->size = 0;
	cache->query = &cache_query;
	cache->insert = &cache_insert;
	return cache;
}