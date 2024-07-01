#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include "../include/log.h"
#include "../include/dns_client.h"
#include "../include/dns_server.h"
#include "../include/query_pool.h"

uv_loop_t *loop;
Cache *cache;
Query_Pool *qpool;
FILE *log_file;

int main(int argc, char *argv[]) {
    init_config(argc, argv);
    log_file = stderr;

    if (LOG_PATH) {
        log_debug("Opening the log file")
        log_file = fopen(LOG_PATH, "w");
        if (!log_file) {
            log_fatal("Failed to open log file")
            exit(1);
        }
    }

    FILE *hosts_file = fopen(HOSTS_PATH, "r");
    if (!hosts_file) {
        log_fatal("Failed to open hosts file")
        exit(1);
    }

    log_info("Starting DNS relay server")
    loop = uv_default_loop();
    cache = new_cache(hosts_file);
    qpool = new_qpool(loop, cache);
	init_client(loop);
    init_server(loop);
    return uv_run(loop, UV_RUN_DEFAULT);
}