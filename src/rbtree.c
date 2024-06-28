#include "../include/rbtree.h"

#include <stdlib.h>
#include <string.h>

#include "../include/dns_conversion.h"
#include "../include/util.h"

static Rbtree_Node *NIL; ///< Leaf node

/**
 * @brief Insert a new element into the linked list
 * @param list The linked list
 * @param new_list_node The new element to insert
 */
static void linklist_insert(Dns_RR_LinkList *list, Dns_RR_LinkList *new_list_node) {
	log_debug("Insert element into link list")
	new_list_node->next = list->next;
	list->next = new_list_node;
}

/**
 * @brief Delete the next element in the linked list
 * @param list The linked list
 */
static void linklist_delete_next(Dns_RR_LinkList *list) {
	log_debug("Delete element from link list")
	Dns_RR_LinkList *temp = list->next;
	list->next = list->next->next;
	destroy_dnsrr(temp->value->rr);
	free(temp->value);
	free(temp);
}

/**
 * @brief Query the next element in the linked list
 * @param list The linked list
 * @param qname The query name
 * @param qtype The query type
 * @return The queried element if found, otherwise NULL
 */
static Dns_RR_LinkList *linklist_query_next(Dns_RR_LinkList *list, const uint8_t *qname, uint16_t qtype) {
	log_debug("Query element in link list")
	time_t now_time = time(NULL);
	while (list->next != NULL) {
		if (list->next->expire_time != -1 && list->next->expire_time <= now_time)
			list = list->next;
		else if (strcmp(list->next->value->rr->name, qname) == 0 &&
		         (list->next->value->type == 255 || list->next->value->type == qtype))
			return list;
		else
			list = list->next;
	}
	return NULL;
}

/**
 * @brief Create a new linked list
 * @return The new linked list
 */
Dns_RR_LinkList *new_linklist() {
	Dns_RR_LinkList *list = (Dns_RR_LinkList *) calloc(1, sizeof(Dns_RR_LinkList));
	if (!list) {
		log_fatal("Memory allocation error")
		return NULL;
	}
	list->next = NULL;

	list->insert = &linklist_insert;
	list->delete_next = &linklist_delete_next;
	list->query_next = &linklist_query_next;
	return list;
}

/**
 * @brief Get the grandparent of a node
 * @param node The current node
 * @return The grandparent node if exists, otherwise NULL
 */
static inline Rbtree_Node *grandparent(Rbtree_Node *node) {
	if (node->parent == NULL)
		return NULL;
	return node->parent->parent;
}

/**
 * @brief Get the uncle of a node
 * @param node The current node
 * @return The uncle node if exists, otherwise NULL
 */
static inline Rbtree_Node *uncle(Rbtree_Node *node) {
	if (grandparent(node) == NULL)
		return NULL;
	if (node->parent == grandparent(node)->right)
		return grandparent(node)->left;
	return grandparent(node)->right;
}

/**
 * @brief Get the sibling of a node
 * @param node The current node
 * @return The sibling node if exists, otherwise NULL
 */
static inline Rbtree_Node *sibling(Rbtree_Node *node) {
	if (node->parent == NULL)
		return NULL;
	if (node->parent->left == node)
		return node->parent->right;
	else
		return node->parent->left;
}

/**
 * @brief Get the smallest child node in a subtree
 * @param node The root of the subtree
 * @return The smallest child node
 */
static Rbtree_Node *smallest_child(Rbtree_Node *node) {
	if (node->left == NIL)
		return node;
	return smallest_child(node->left);
}

/**
 * @brief Rotate a node to the right
 * @param tree The tree that the node belongs to
 * @param node The current node
 */
static void rotate_right(Rbtree *tree, Rbtree_Node *node) {
	if (node->parent == NULL) {
		tree->root = node;
		return;
	}
	Rbtree_Node *gp = grandparent(node);
	Rbtree_Node *fa = node->parent;
	Rbtree_Node *y = node->right;
	fa->left = y;
	if (y != NIL)
		y->parent = fa;
	node->right = fa;
	fa->parent = node;
	if (tree->root == fa)
		tree->root = node;
	node->parent = gp;
	if (gp != NULL) {
		if (gp->left == fa)
			gp->left = node;
		else
			gp->right = node;
	}
}

/**
 * @brief Rotate a node to the left
 * @param tree The tree that the node belongs to
 * @param node The current node
 */
static void rotate_left(Rbtree *tree, Rbtree_Node *node) {
	if (node->parent == NULL) {
		tree->root = node;
		return;
	}
	Rbtree_Node *gp = grandparent(node);
	Rbtree_Node *fa = node->parent;
	Rbtree_Node *y = node->left;
	fa->right = y;
	if (y != NIL)
		y->parent = fa;
	node->left = fa;
	fa->parent = node;
	if (tree->root == fa)
		tree->root = node;
	node->parent = gp;
	if (gp != NULL) {
		if (gp->left == fa)
			gp->left = node;
		else
			gp->right = node;
	}
}

/**
 * @brief Adjust the shape of the red-black tree to keep it balanced
 * @param tree The tree that the node belongs to
 * @param node The current node
 */
static void insert_case(Rbtree *tree, Rbtree_Node *node) {
	if (node->parent == NULL) {
		tree->root = node;
		node->color = BLACK;
		return;
	}
	if (node->parent->color == RED) {
		if (uncle(node)->color == RED) {
			node->parent->color = uncle(node)->color = BLACK;
			grandparent(node)->color = RED;
			insert_case(tree, grandparent(node));
		} else {
			if (node->parent->right == node && grandparent(node)->left == node->parent) {
				rotate_left(tree, node);
				node->color = BLACK;
				node->parent->color = RED;
				rotate_right(tree, node);
			} else if (node->parent->left == node && grandparent(node)->right == node->parent) {
				rotate_right(tree, node);
				node->color = BLACK;
				node->parent->color = RED;
				rotate_left(tree, node);
			} else if (node->parent->left == node && grandparent(node)->left == node->parent) {
				node->parent->color = BLACK;
				grandparent(node)->color = RED;
				rotate_right(tree, node->parent);
			} else if (node->parent->right == node && grandparent(node)->right == node->parent) {
				node->parent->color = BLACK;
				grandparent(node)->color = RED;
				rotate_left(tree, node->parent);
			}
		}
	}
}

/**
 * @brief Initialize a node and allocate memory
 * @param key The key of the node
 * @param list The value of the node
 * @param fa The parent node
 * @return A pointer to the new node
 */
static Rbtree_Node *node_init(unsigned int key, Dns_RR_LinkList *list, Rbtree_Node *fa) {
	Rbtree_Node *node = (Rbtree_Node *) calloc(1, sizeof(Rbtree_Node));
	if (!node)
		log_fatal("Memory allocation error")
	node->key = key;
	node->rr_list = new_linklist();
	node->rr_list->insert(node->rr_list, list);
	node->color = RED;
	node->left = node->right = NIL;
	node->parent = fa;
	return node;
}

/**
 * @brief Insert a key-value pair into the red-black tree
 * @param tree The red-black tree
 * @param key The key
 * @param list The value
 */
void rbtree_insert(Rbtree *tree, unsigned int key, Dns_RR_LinkList *list) {
	log_debug("Insert into Red-Black Tree")
	Rbtree_Node *node = tree->root;
	if (node == NULL) {
		node = node_init(key, list, NULL);
		insert_case(tree, node);
		return;
	}
	while (1) {
		if (key < node->key) {
			if (node->left != NIL)node = node->left;
			else {
				Rbtree_Node *new_node = node_init(key, list, node);
				node->left = new_node;
				insert_case(tree, new_node);
				return;
			}
		} else if (key > node->key) {
			if (node->right != NIL)node = node->right;
			else {
				Rbtree_Node *new_node = node_init(key, list, node);
				node->right = new_node;
				insert_case(tree, new_node);
				return;
			}
		} else {
			node->rr_list->insert(node->rr_list, list);
			return;
		}
	}
}

/**
 * @brief Recursively search for a node with a given key starting from a given node
 * @param node The current node
 * @param key The key to search for
 * @return A pointer to the node if found, otherwise NULL
 */
static Rbtree_Node *rbtree_find(Rbtree_Node *node, unsigned int key) {
	if (node->key > key) {
		if (node->left == NIL)return NULL;
		return rbtree_find(node->left, key);
	} else if (node->key < key) {
		if (node->right == NIL)return NULL;
		return rbtree_find(node->right, key);
	} else return node;
}

/**
 * @brief Destroy a node in the red-black tree
 * @param node The node to destroy
 * @note The linked list of the node is assumed to be empty (i.e., only the head node)
 */
static void destroy_node(Rbtree_Node *node) {
	free(node->rr_list);
	free(node);
	node = NULL;
}

/**
 * @brief Adjust the shape of the red-black tree to keep it balanced
 * @param tree The tree that the node belongs to
 * @param node The current node
 */
static void delete_case(Rbtree *tree, Rbtree_Node *node) {
	if (node->parent == NULL) {
		node->color = BLACK;
		return;
	}
	if (sibling(node)->color == RED) {
		node->parent->color = RED;
		sibling(node)->color = BLACK;
		if (node == node->parent->left)
			rotate_left(tree, sibling(node));
		else
			rotate_right(tree, sibling(node));
	}
	if (node->parent->color == BLACK && sibling(node)->color == BLACK
	    && sibling(node)->left->color == BLACK && sibling(node)->right->color == BLACK) {
		sibling(node)->color = RED;
		delete_case(tree, node->parent);
	} else if (node->parent->color == RED && sibling(node)->color == BLACK
	           && sibling(node)->left->color == BLACK && sibling(node)->right->color == BLACK) {
		sibling(node)->color = RED;
		node->parent->color = BLACK;
	} else {
		if (sibling(node)->color == BLACK) {
			if (node == node->parent->left && sibling(node)->left->color == RED
			    && sibling(node)->right->color == BLACK) {
				sibling(node)->color = RED;
				sibling(node)->left->color = BLACK;
				rotate_right(tree, sibling(node)->left);
			} else if (node == node->parent->right && sibling(node)->left->color == BLACK
			           && sibling(node)->right->color == RED) {
				sibling(node)->color = RED;
				sibling(node)->right->color = BLACK;
				rotate_left(tree, sibling(node)->right);
			}
		}
		sibling(node)->color = node->parent->color;
		node->parent->color = BLACK;
		if (node == node->parent->left) {
			sibling(node)->right->color = BLACK;
			rotate_left(tree, sibling(node));
		} else {
			sibling(node)->left->color = BLACK;
			rotate_right(tree, sibling(node));
		}
	}
}

/**
 * @brief Delete a node from the red-black tree
 * @param tree The tree that the node belongs to
 * @param node The node to delete
 */
static void rbtree_delete(Rbtree *tree, Rbtree_Node *node) {
	log_debug("Delete node from Red-Black Tree")
	if (node->right != NIL) {
		Rbtree_Node *smallest = smallest_child(node->right);
		Dns_RR_LinkList *temp = node->rr_list;
		node->rr_list = smallest->rr_list;
		smallest->rr_list = temp;
		unsigned int temp1 = node->key;
		node->key = smallest->key;
		smallest->key = temp1;
		node = smallest;
	}
	Rbtree_Node *child = node->left == NIL ? node->right : node->left;
	if (node->parent == NULL) {
		if (node->left == NIL && node->right == NIL)
			tree->root = NULL;
		else {
			child->parent = NULL;
			tree->root = child;
			tree->root->color = BLACK;
		}
		destroy_node(node);
		return;
	}
	if (node->parent->left == node)
		node->parent->left = child;
	else
		node->parent->right = child;
	if (child != NIL)
		child->parent = node->parent;
	if (node->color == BLACK) {
		if (child->color == RED)
			child->color = BLACK;
		else
			delete_case(tree, child);
	}
	destroy_node(node);
}

/**
 * @brief Query the red-black tree for a key
 * @param tree The red-black tree
 * @param key The key to query
 * @return The linked list of the value if found, otherwise NULL
 */
Dns_RR_LinkList *rbtree_query(Rbtree *tree, unsigned int key) {
	log_debug("Query in Red-Black Tree")
	Rbtree_Node *node = rbtree_find(tree->root, key);
	if (node == NULL)return NULL;
	time_t now_time = time(NULL);
	Dns_RR_LinkList *list = node->rr_list;
	while (list->next != NULL) {
		if (list->next->expire_time != -1 && list->next->expire_time <= now_time)
			list->delete_next(list);
		else
			list = list->next;
	}
	if (node->rr_list->next != NULL)
		return node->rr_list->next;
	else {
		rbtree_delete(tree, node);
		return NULL;
	}
}

/**
 * @brief Initialize a new red-black tree
 * This function allocates memory for a new red-black tree and its nil node,
 * and sets up the tree's function pointers for insertion and querying.
 * @return A pointer to the newly created red-black tree
 * @note If memory allocation fails, the function will log a fatal error and terminate the program.
 */
Rbtree *new_rbtree() {
	log_debug("Red-Black Tree Init")
	Rbtree *tree = (Rbtree *) calloc(1, sizeof(Rbtree));
	if (!tree)
		log_fatal("Memory allocation error")
	tree->root = NULL;
	if (!NIL) {
		NIL = (Rbtree_Node *) calloc(1, sizeof(Rbtree_Node));
		if (!NIL)
			log_fatal("Memory allocation error")
		NIL->color = BLACK;
		NIL->left = NIL->right = NIL;
	}

	tree->insert = &rbtree_insert;
	tree->query = &rbtree_query;
	return tree;
}