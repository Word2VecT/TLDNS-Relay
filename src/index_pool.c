#include "../include/index_pool.h"

#include <stdlib.h>

#include "../include/util.h"

/**
 * @brief Check if the index pool is full
 * @param ipool The index pool
 * @return True if the index pool is full, false otherwise
 */
static bool ipool_full(Index_Pool *ipool) {
	return ipool->count == INDEX_POOL_MAX_SIZE;
}

/**
 * @brief Insert an index into the pool
 * @param ipool The index pool
 * @param req The index to insert
 * @return The ID of the inserted index
 */
static uint16_t ipool_insert(Index_Pool *ipool, Index *req) {
	uint16_t id = ipool->queue->pop(ipool->queue);
	ipool->pool[id] = req;
	ipool->count++;
	return id;
}

/**
 * @brief Query if an index exists in the pool
 * @param ipool The index pool
 * @param index The index to query
 * @return True if the index exists, false otherwise
 */
static bool ipool_query(Index_Pool *ipool, uint16_t index) {
	return ipool->pool[index] != NULL;
}

/**
 * @brief Delete an index from the pool
 * @param ipool The index pool
 * @param index The index to delete
 * @return The deleted index
 */
static Index *ipool_delete(Index_Pool *ipool, uint16_t index) {
	Index *req = ipool->pool[index];
	ipool->queue->push(ipool->queue, index);
	ipool->pool[index] = NULL;
	ipool->count--;
	return req;
}

/**
 * @brief Destroy the index pool
 * @param ipool The index pool to destroy
 */
static void ipool_destroy(Index_Pool *ipool) {
	ipool->queue->destroy(ipool->queue);
	free(ipool);
}

/**
 * @brief Create a new index pool
 * @return The new index pool
 */
Index_Pool *new_ipool() {
	Index_Pool *ipool = (Index_Pool *) calloc(1, sizeof(Index_Pool));
	if (!ipool) {
		log_fatal("Memory allocation error")
		return NULL;
	}
	ipool->count = 0;
	ipool->queue = new_queue();
	for (uint16_t i = 0; i < INDEX_POOL_MAX_SIZE; ++i)
		ipool->queue->push(ipool->queue, i);

	ipool->full = &ipool_full;
	ipool->insert = &ipool_insert;
	ipool->query = &ipool_query;
	ipool->delete = &ipool_delete;
	ipool->destroy = &ipool_destroy;
	return ipool;
}