#ifndef DNSR_RBTREE_H
#define DNSR_RBTREE_H

#include <time.h>

#include "dns_structure.h"

/// Red-Black Tree color
typedef enum {
	BLACK, RED
} Color;

/// Value of a Red-Black Tree node's linked list, corresponding to an answer for a specific query
typedef struct rbtree_value {
	Dns_RR *rr; ///< Pointer to a linked list of Dns_RR
	uint16_t ancount; ///< Number of RRs in the Answer Section
	uint16_t nscount; ///< Number of RRs in the Authority Section
	uint16_t arcount; ///< Number of RRs in the Additional Section
	uint8_t type; ///< Type of the Question corresponding to the RR
} Rbtree_Value;

/// Linked list of Red-Black Tree nodes
typedef struct dns_rr_linklist {
	Rbtree_Value *value; ///< Pointer to the value of the current linked list node
	time_t expire_time; ///< Expiration time
	struct dns_rr_linklist *next; ///< Pointer to the next node in the linked list

	/**
	 * @brief Insert a key-value pair into the red-black tree
	 * @param tree The red-black tree
	 * @param key The key
	 * @param list The value
	 */
	void (*insert)(struct dns_rr_linklist *list, struct dns_rr_linklist *new_list_node);

	/**
	 * @brief Delete the next element in the linked list
	 * @param list The linked list
	 */
	void (*delete_next)(struct dns_rr_linklist *list);

	/**
	 * @brief Query the next element in the linked list
	 * @param list The linked list
	 * @param qname The query name
	 * @param qtype The query type
	 * @return The queried element if found, otherwise NULL
	 */
	struct dns_rr_linklist *(*query_next)(struct dns_rr_linklist *list, const uint8_t *qname, const uint16_t qtype);
} Dns_RR_LinkList;

/// Node of the Red-Black Tree
typedef struct rbtree_node {
	unsigned int key; ///< Key of the Red-Black Tree node
	Dns_RR_LinkList *rr_list; ///< Pointer to the linked list corresponding to the current node
	Color color; ///< Color of the current node
	struct rbtree_node *left; ///< Pointer to the left child of the current node
	struct rbtree_node *right; ///< Pointer to the right child of the current node
	struct rbtree_node *parent; ///< Pointer to the parent of the current node
} Rbtree_Node;

/// Red-Black Tree
typedef struct rbtree {
	Rbtree_Node *root; ///< Pointer to the root node of the Red-Black Tree

	/**
	 * @brief Insert a key-value pair into the red-black tree
	 * @param tree The red-black tree
	 * @param key The key
	 * @param list The value
	 */
	void (*insert)(struct rbtree *tree, unsigned int key, Dns_RR_LinkList *list);

	/**
	 * @brief Query the red-black tree for a key
	 * @param tree The red-black tree
	 * @param key The key to query
	 * @return The linked list of the value if found, otherwise NULL
	 */
	Dns_RR_LinkList *(*query)(struct rbtree *tree, unsigned int data);
} Rbtree;

/**
 * @brief Create a new linked list
 * @return The new linked list
 */
Dns_RR_LinkList *new_linklist();

/**
 * @brief Initialize a new red-black tree
 * This function allocates memory for a new red-black tree and its nil node,
 * and sets up the tree's function pointers for insertion and querying.
 * @return A pointer to the newly created red-black tree
 * @note If memory allocation fails, the function will log a fatal error and terminate the program.
 */
Rbtree *new_rbtree();

#endif //DNSR_RBTREE_H