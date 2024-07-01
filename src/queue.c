#include "../include/queue.h"

#include <stdlib.h>

#include "../include/log.h"

/**
 * @brief Push a number onto the queue
 * @param queue The queue
 * @param num The number to push
 */
static void queue_push(Queue *queue, uint16_t num) {
	queue->q[++queue->tail] = num;
}

/**
 * @brief Pop a number from the queue
 * @param queue The queue
 * @return The number popped from the queue
 */
static uint16_t queue_pop(Queue *queue) {
	return queue->q[queue->head++];
}

/**
 * @brief Destroy the queue
 * @param queue The queue to destroy
 */
static void queue_destroy(Queue *queue) {
	free(queue);
}

/**
 * @brief Create a new queue
 * @return The new queue
 */
Queue *new_queue() {
	Queue *queue = (Queue *) calloc(1, sizeof(Queue));
	if (!queue) {
		log_fatal("Memory allocation error")
		return NULL;
	}
	queue->head = 0;
	queue->tail = QUEUE_MAX_SIZE - 1;

	queue->push = &queue_push;
	queue->pop = &queue_pop;
	queue->destroy = &queue_destroy;
	return queue;
}