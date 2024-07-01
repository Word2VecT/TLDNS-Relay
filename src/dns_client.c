// TODO: 形参未使用

#include "../include/dns_client.h"

#include <stdlib.h>

#include "../include/log.h"
#include "../include/dns_parse.h"
#include "../include/dns_print.h"
#include "../include/query_pool.h"

static uv_udp_t client_socket; ///< Socket for client communication with the remote server
static struct sockaddr_in local_addr; ///< Local address
static struct sockaddr send_addr; ///< Remote server address
extern Query_Pool *qpool; ///< Query pool

/**
 * @brief Allocate space for the buffer
 * @param handle Allocation handle
 * @param suggested_size Suggested buffer size
 * @param buf Buffer to be allocated
 */
static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
	buf->base = (char *) calloc(DNS_STRING_MAX_SIZE, sizeof(char));
	if (!buf->base)
		log_fatal("Memory allocation error")
	buf->len = DNS_STRING_MAX_SIZE;
}

/**
 * @brief Callback function for receiving response messages from the remote server
 * @param handle Query handle
 * @param nread Number of bytes received
 * @param buf Buffer containing the received message
 * @param addr Address of the sender
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
	log_info("Received message from server")
	print_dns_string(buf->base, nread);
	Dns_Msg *msg = (Dns_Msg *) calloc(1, sizeof(Dns_Msg));
	if (!msg)
		log_fatal("Memory allocation error")
	string_to_dnsmsg(msg, buf->base);
	print_dns_message(msg);
	qpool->finish(qpool, msg);
	destroy_dnsmsg(msg);
	if (buf->base)
		free(buf->base);
}

/**
 * @brief Callback function for sending query messages to the remote server
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
 * @brief Initialize the DNS client
 * @param loop The libuv event loop
 */
void init_client(uv_loop_t *loop) {
	log_info("Starting client")
	uv_udp_init(loop, &client_socket);
	uv_ip4_addr("0.0.0.0", CLIENT_PORT, &local_addr);
	uv_udp_bind(&client_socket, (const struct sockaddr *) &local_addr, UV_UDP_REUSEADDR);
	uv_udp_set_broadcast(&client_socket, 1);
	uv_ip4_addr(REMOTE_HOST, 53, (struct sockaddr_in *) &send_addr);
	uv_udp_recv_start(&client_socket, alloc_buffer, on_read);
}

/**
 * @brief Send a DNS query message to the remote server
 * @param msg The DNS message to be sent
 */
void send_to_remote(const Dns_Msg *msg) {
	char *str = (char *) calloc(DNS_STRING_MAX_SIZE, sizeof(char));
	if (!str)
		log_fatal("Memory allocation error")
	unsigned int len = dnsmsg_to_string(msg, str);

	uv_udp_send_t *req = malloc(sizeof(uv_udp_send_t));
	if (!req) {
		log_fatal("Memory allocation error")
		return;
	}
	uv_buf_t send_buf = uv_buf_init((char *) malloc(len), len);
	memcpy(send_buf.base, str, len);
	req->data = (char **) malloc(sizeof(char **));
	*(char **) (req->data) = send_buf.base;

	log_info("Sending message to server")
	print_dns_message(msg);
	print_dns_string(send_buf.base, len);
	uv_udp_send(req, &client_socket, &send_buf, 1, &send_addr, on_send);
	free(str);
}