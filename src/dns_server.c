#include "../include/dns_server.h"

#include <stdlib.h>

#include "../include/log.h"
#include "../include/dns_parse.h"
#include "../include/dns_print.h"
#include "../include/query_pool.h"

static uv_udp_t server_socket; ///< Socket for server communication with local clients
static struct sockaddr_in recv_addr; ///< Address for receiving DNS query messages
extern Query_Pool *qpool; ///< Query pool

/**
 * @brief Allocate space for the buffer
 * @param handle Allocation handle
 * @param suggested_size Suggested buffer size
 * @param buf Buffer to be allocated
 *
 * Allocates a buffer of fixed size DNS_STRING_MAX_SIZE for receiving DNS query messages from local clients.
 */
static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
	buf->base = (char *) calloc(DNS_STRING_MAX_SIZE, sizeof(char));
	if (!buf->base)
		log_fatal("Memory allocation error")
	buf->len = DNS_STRING_MAX_SIZE;
}

/**
 * @brief Callback function for sending response messages to local clients
 * @param req Send handle
 * @param status Send status, indicating whether the send was successful
 */
static void on_send(uv_udp_send_t *req, int status) {
	free(*(char **) req->data);
	free(req->data);
	free(req);
	if (status)
		log_error("Send status error %d", status)
}

/**
 * @brief Callback function for receiving query messages from local clients
 * @param handle Query handle
 * @param nread Number of bytes received
 * @param buf Buffer containing the received message
 * @param addr Address of the local sender
 * @param flags Flags indicating special conditions for the received data
 */
static void on_read(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
	if (nread < 0) {
		if (buf->base)
			free(buf->base);
		log_debug("Transmission error")
		return;
	}
	if (nread == 0) {
		if (buf->base)
			free(buf->base);
		return;
	}
	log_debug("Received DNS query message from local client")
	print_dns_string(buf->base, nread);
	Dns_Msg *msg = (Dns_Msg *) calloc(1, sizeof(Dns_Msg));
	if (!msg)
		log_fatal("Memory allocation error")
	string_to_dnsmsg(msg, buf->base); // Convert byte sequence to structure
	print_dns_message(msg);

	if (qpool->full(qpool)) {
		log_error("Query pool full")
	} else
		qpool->insert(qpool, addr, msg); // Add DNS query to the query pool
	destroy_dnsmsg(msg);
	if (buf->base)
		free(buf->base);
}

/**
 * @brief Initialize the DNS server
 * @param loop The libuv event loop
 */
void init_server(uv_loop_t *loop) {
	log_info("Starting server")
	uv_udp_init(loop, &server_socket); // Bind server_socket to the event loop
	uv_ip4_addr("0.0.0.0", 53, &recv_addr); // Initialize recv_addr to 0.0.0.0:53
	uv_udp_bind(&server_socket, (struct sockaddr *) &recv_addr, UV_UDP_REUSEADDR);
	uv_udp_recv_start(&server_socket, alloc_buffer,
	                  on_read); // On receiving DNS query messages, allocate buffer and call callback function
}

/**
 * @brief Send a DNS response message to local clients
 * @param addr The address of the local client
 * @param msg The DNS message to be sent
 */
void send_to_local(const struct sockaddr *addr, const Dns_Msg *msg) {
	log_info("Sending DNS response message to local client")
	print_dns_message(msg);
	char *str = (char *) calloc(DNS_STRING_MAX_SIZE, sizeof(char)); // Convert DNS structure to byte stream
	if (!str)
		log_fatal("Memory allocation error")
	unsigned int len = dnsmsg_to_string(msg, str);
	uv_udp_send_t *req = malloc(sizeof(uv_udp_send_t));
	if (!req) {
		log_fatal("Memory allocation error")
		return;
	}

	uv_buf_t send_buf = uv_buf_init((char *) malloc(len), len);
	memcpy(send_buf.base, str, len); // Store byte sequence in send buffer
	req->data = (char **) malloc(sizeof(char **));
	*(char **) (req->data) = send_buf.base;
	print_dns_string(send_buf.base, len);

	uv_udp_send(req, &server_socket, &send_buf, 1, addr, on_send);
	free(str);
}