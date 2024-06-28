#ifndef DNSR_CACHE_H
#define DNSR_CACHE_H

#include <stdio.h>

#include "rbtree.h"

#define CACHE_SIZE 30

/// Cash struct
typedef struct cache_
{
    Dns_RR_LinkList * head; ///< LRU header node
    Dns_RR_LinkList * tail; ///< LRU tail node
    int size; ///< LRU size
    Rbtree * tree; ///< Red–black tree

	/**
 	* @brief Insert a DNS message into the cache.
 	* @param cache The cache where the message will be inserted.
	* @param msg The DNS message to be inserted.
 	*/
    void (* insert)(struct cache_ * cache, const Dns_Msg * msg);

	/**
 	* @brief Query the cache for a DNS question.
 	* @param cache The cache to query.
 	* @param que The DNS question.
	* @return The value found in the cache or NULL if not found.
 	*/
    Rbtree_Value * (* query)(struct cache_ * cache, const Dns_Que * que);
} Cache;

/**
 * @brief Create a new cache and initialize it with data from the hosts file.
 * @param hosts_file The file containing hosts data.
 * @return The newly created cache.
 */
Cache * new_cache(FILE * hosts_file);

#endif //DNSR_CACHE_H