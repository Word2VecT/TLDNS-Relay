#ifndef DNSR_QUERY_POOL_H
#define DNSR_QUERY_POOL_H

#include <stdbool.h>
#include <uv.h>

#include "dns.h"
#include "index_pool.h"
#include "cache.h"

#define QUERY_POOL_MAX_SIZE 256

/// DNS query structure
typedef struct dns_query {
	uint16_t id; ///< Query ID
	uint16_t prev_id; ///< Original DNS query message ID
	struct sockaddr addr; ///< Address of the requester
	Dns_Msg * msg; ///< DNS query message
	uv_timer_t timer; ///< Timer
} Dns_Query;

/// DNS query pool
typedef struct query_pool {
	Dns_Query * pool[QUERY_POOL_MAX_SIZE]; ///< Query pool
	unsigned short count; ///< Number of queries in the pool
	Queue * queue; ///< Queue of unassigned query IDs
	Index_Pool * ipool; ///< Index pool
	uv_loop_t * loop; ///< Event loop
	Cache * cache; ///< Cache

	/**
 	* @brief Check if the query pool is full
 	* @param this The query pool
 	* @return true if the query pool is full, false otherwise
 	*/
	bool (* full)(struct query_pool * qpool);

	/**
 	* @brief Insert a new query into the query pool
 	* This function creates a new query and inserts it into the query pool.
 	* If the query is found in the cache, it is immediately processed and sent to the local client.
 	* Otherwise, it is sent to the remote DNS server and a timeout timer is started.
 	* @param qpool The query pool
 	* @param addr The address of the client
 	* @param msg The DNS message containing the query
 	*/
	void (* insert)(struct query_pool * qpool, const struct sockaddr * addr, const Dns_Msg * msg);

	/**
 	* @brief Finish processing a query
 	* This function is called when a response is received for a query.
 	* It processes the response, updates the cache if necessary, and sends the response to the local client.
 	* @param qpool The query pool
 	* @param msg The DNS message containing the response
 	*/
	void (* finish)(struct query_pool * qpool, const Dns_Msg * msg);

	/**
 	* @brief Delete a query from the query pool
 	* This function deletes a query from the query pool and frees the associated resources.
 	* @param qpool The query pool
 	* @param id The ID of the query to be deleted
 	*/
	void (* delete)(struct query_pool * qpool, uint16_t id);
} Query_Pool;

/**
 * @brief Create a new query pool
 * This function initializes a new query pool and returns a pointer to it.
 * @param loop The libuv event loop
 * @param cache The cache used for storing DNS responses
 * @return A pointer to the newly created query pool
 */
Query_Pool *new_qpool(uv_loop_t * loop, Cache * cache);

#endif //DNSR_QUERY_POOL_H