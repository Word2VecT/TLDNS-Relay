#ifndef DNSR_INDEX_POOL_H
#define DNSR_INDEX_POOL_H

#include <stdbool.h>

#include "queue.h"

#define INDEX_POOL_MAX_SIZE 65535

/// Index structure
typedef struct index_
{
	uint16_t id; ///< The ID of the sent DNS query message
	uint16_t prev_id; ///< The corresponding query ID
} Index;

/// Index pool
typedef struct index_pool
{
	Index * pool[INDEX_POOL_MAX_SIZE]; ///< Index pool
	unsigned short count; ///< Number of indices in the pool
	Queue * queue; ///< Queue of unallocated indices

	/**
	 * @brief Check if the index pool is full
	 * @param ipool The index pool
	 * @return True if the index pool is full, false otherwise
	 */
	bool (* full)(struct index_pool * ipool);

	/**
	 * @brief Insert an index into the pool
	 * @param ipool The index pool
	 * @param req The index to insert
	 * @return The ID of the inserted index
	 */
	uint16_t (* insert)(struct index_pool * ipool, Index * req);

	/**
	 * @brief Query if an index exists in the pool
	 * @param ipool The index pool
	 * @param index The index to query
	 * @return True if the index exists, false otherwise
	 */
	bool (* query)(struct index_pool * ipool, uint16_t index);

	/**
	* @brief Delete an index from the pool
	* @param ipool The index pool
	* @param index The index to delete
	* @return The deleted index
	*/
	Index * (* delete)(struct index_pool * ipool, uint16_t index);

	/**
	 * @brief Destroy the index pool
	 * @param ipool The index pool to destroy
	 */
	void (* destroy)(struct index_pool * ipool);
} Index_Pool;

/**
 * @brief Create a new index pool
 * @return The new index pool
 */
Index_Pool * new_ipool();

#endif //DNSR_INDEX_POOL_H