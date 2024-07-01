#include "../include/query_pool.h"

#include <stdlib.h>

#include "../include/log.h"
#include "../include/dns_parse.h"
#include "../include/dns_client.h"
#include "../include/dns_server.h"

/**
 * @brief Timeout callback function
 * This function is called when a query times out.
 * It stops the timer and deletes the query from the query pool.
 * @param timer The timer that timed out
 */
static void timeout_cb(uv_timer_t *timer) {
	log_info("Timeout")
	uv_timer_stop(timer);
	Query_Pool *qpool = *(Query_Pool **) (timer->data + sizeof(uint16_t));
	qpool->delete(qpool, *(uint16_t *) timer->data);
}

/**
 * @brief Check if the query pool is full
 * @param this The query pool
 * @return true if the query pool is full, false otherwise
 */
static bool qpool_full(Query_Pool *this) {
	return this->count == QUERY_POOL_MAX_SIZE;
}

/**
 * @brief Insert a new query into the query pool
 * This function creates a new query and inserts it into the query pool.
 * If the query is found in the cache, it is immediately processed and sent to the local client.
 * Otherwise, it is sent to the remote DNS server and a timeout timer is started.
 * @param qpool The query pool
 * @param addr The address of the client
 * @param msg The DNS message containing the query
 */
static void qpool_insert(Query_Pool *qpool, const struct sockaddr *addr, const Dns_Msg *msg) {
	log_debug("Adding new query request")
	Dns_Query *query = (Dns_Query *) calloc(1, sizeof(Dns_Query));
	if (!query) {
		log_fatal("Memory allocation error")
		return;
	}
	uint16_t id = qpool->queue->pop(qpool->queue);
	qpool->pool[id % QUERY_POOL_MAX_SIZE] = query;
	qpool->count++;

	query->id = id;
	query->prev_id = msg->header->id;
	query->addr = *addr;
	query->msg = copy_dnsmsg(msg);

	Rbtree_Value *value = qpool->cache->query(qpool->cache, query->msg->que);
	if (value != NULL) {
		query->msg->header->qr = DNS_QR_ANSWER;
		if (query->msg->header->rd == 1) query->msg->header->ra = 1;
		query->msg->header->ancount = value->ancount;
		query->msg->header->nscount = value->nscount;
		query->msg->header->arcount = value->arcount;
		query->msg->rr = value->rr;

		// Poisoning
		if (value->rr->type == 255 && (*(int *) value->rr->rdata) == 0) {
			query->msg->header->rcode = DNS_RCODE_NXDOMAIN;
			destroy_dnsrr(query->msg->rr);
			query->msg->rr = NULL;
			query->msg->header->ancount = 0;
		}

		send_to_local(addr, query->msg);
		free(value);
		qpool->delete(qpool, query->id);
	} else {
		if (qpool->ipool->full(qpool->ipool)) {
			log_error("Index pool full")
			qpool->delete(qpool, id);
			return;
		}
		Index *index = (Index *) calloc(1, sizeof(Index));
		if (!index) {
			log_fatal("Memory allocation error")
			return;
		}
		index->id = qpool->ipool->insert(qpool->ipool, index);
		index->prev_id = id;
		query->msg->header->id = index->id;

		uv_timer_init(qpool->loop, &query->timer);
		query->timer.data = malloc(sizeof(uint16_t) + sizeof(Query_Pool *));
		if (!query->timer.data)
			log_fatal("Memory allocation error")
		*(uint16_t *) query->timer.data = query->id;
		*(Query_Pool **) (query->timer.data + sizeof(uint16_t)) = qpool;
		uv_timer_start(&query->timer, timeout_cb, 5000, 5000);
		send_to_remote(query->msg);
	}
}

/**
 * @brief Check if a query exists in the query pool
 * @param qpool The query pool
 * @param id The ID of the query
 * @return true if the query exists in the query pool, false otherwise
 */
static bool qpool_query(Query_Pool *qpool, uint16_t id) {
	return qpool->pool[id % QUERY_POOL_MAX_SIZE] != NULL && qpool->pool[id % QUERY_POOL_MAX_SIZE]->id == id;
}

/**
 * @brief Finish processing a query
 * This function is called when a response is received for a query.
 * It processes the response, updates the cache if necessary, and sends the response to the local client.
 * @param qpool The query pool
 * @param msg The DNS message containing the response
 */
static void qpool_finish(Query_Pool *qpool, const Dns_Msg *msg) {
	uint16_t uid = msg->header->id;
	if (!qpool->ipool->query(qpool->ipool, uid)) {
		log_error("Index not found in the index pool")
		return;
	}
	Index *index = qpool->ipool->delete(qpool->ipool, uid);
	if (qpool_query(qpool, index->prev_id)) {
		Dns_Query *query = qpool->pool[index->prev_id % QUERY_POOL_MAX_SIZE];
		log_debug("Finishing query ID: 0x%04x", query->id)

		if (strcmp((char *)msg->que->qname, (char *)query->msg->que->qname) == 0) {
			destroy_dnsmsg(query->msg);
			query->msg = copy_dnsmsg(msg);
			query->msg->header->id = query->prev_id;
			if (msg->header->rcode == DNS_RCODE_OK &&
			    (msg->que->qtype == DNS_TYPE_A || msg->que->qtype == DNS_TYPE_CNAME ||
			     msg->que->qtype == DNS_TYPE_AAAA))
				qpool->cache->insert(qpool->cache, msg);
			send_to_local(&query->addr, query->msg);
		}
		qpool->delete(qpool, query->id);
	}
	free(index);
}

/**
 * @brief Delete a query from the query pool
 * This function deletes a query from the query pool and frees the associated resources.
 * @param qpool The query pool
 * @param id The ID of the query to be deleted
 */
static void qpool_delete(Query_Pool *qpool, uint16_t id) {
	if (!qpool_query(qpool, id)) {
		log_error("Query ID not found in the query pool")
		return;
	}
	log_debug("Deleting query ID: 0x%04x", id)
	Dns_Query *query = qpool->pool[id % QUERY_POOL_MAX_SIZE];
	if (!query) {
		log_error("Query is NULL");
		return;
	}
	qpool->queue->push(qpool->queue, id + QUERY_POOL_MAX_SIZE);
	qpool->pool[id % QUERY_POOL_MAX_SIZE] = NULL;
	qpool->count--;
	log_debug("Deleting query timer: %p", &query->timer);
	if (query->timer.data) {
		log_debug("Deleting query timer: %p", &query->timer);
		uv_timer_stop(&query->timer);
		free(query->timer.data);
	} else {
		log_debug("Query timer data is NULL, skipping uv_timer_stop");
	}
	destroy_dnsmsg(query->msg);
	free(query);
}

/**
 * @brief Create a new query pool
 * This function initializes a new query pool and returns a pointer to it.
 * @param loop The libuv event loop
 * @param cache The cache used for storing DNS responses
 * @return A pointer to the newly created query pool
 */
Query_Pool *new_qpool(uv_loop_t *loop, Cache *cache) {
	log_info("Initializing query pool")
	Query_Pool *qpool = (Query_Pool *) calloc(1, sizeof(Query_Pool));
	if (!qpool) {
		log_fatal("Memory allocation error")
		return NULL;
	}
	qpool->count = 0;
	qpool->queue = new_queue();
	for (uint16_t i = 0; i < QUERY_POOL_MAX_SIZE; ++i)
		qpool->queue->push(qpool->queue, i);
	qpool->ipool = new_ipool();
	qpool->loop = loop;
	qpool->cache = cache;

	qpool->full = &qpool_full;
	qpool->insert = &qpool_insert;
	qpool->delete = &qpool_delete;
	qpool->finish = &qpool_finish;
	return qpool;
}