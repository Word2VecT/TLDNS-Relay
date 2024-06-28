#include <stdint.h>

#ifndef DNSR_QUEUE_H
#define DNSR_QUEUE_H

#define QUEUE_MAX_SIZE 65536

/// Circular queue
typedef struct queue
{
	uint16_t q[QUEUE_MAX_SIZE]; ///< The queue
	unsigned short head; ///< The head of the queue
	unsigned short tail; ///< The tail of the queue

	/**
	 * @brief Push a number onto the queue
	 * @param queue The queue
	 * @param num The number to push
	 */
	void (* push)(struct queue * queue, uint16_t num);

	/**
	 * @brief Pop a number from the queue
	 * @param queue The queue
	 * @return The number popped from the queue
	 */
	uint16_t (* pop)(struct queue * queue);

	/**
	 * @brief Destroy the queue
	 * @param queue The queue to destroy
	 */
	void (* destroy)(struct queue * queue);
} Queue;

/**
 * @brief Create a new queue
 * @return The new queue
 */
Queue * new_queue();

#endif //DNSR_QUEUE_H