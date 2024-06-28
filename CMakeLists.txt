cmake_minimum_required(VERSION 3.17)
project(dnsr C)

set(CMAKE_C_STANDARD 23)

set(UV_DIR /opt/homebrew/Cellar/libuv/1.48.0)

link_directories(${UV_DIR}/lib/)
include_directories(${UV_DIR}/include/)

add_executable(main
        src/main.c
        include/util.h
        src/config.c
        include/config.h
        include/dns_structure.h
        src/dns_parse.c
        include/dns_parse.h
        src/dns_client.c
        include/dns_client.h
        src/dns_server.c
        include/dns_server.h
        src/index_pool.c
        include/index_pool.h
        src/queue.c
        include/queue.h
        src/dns_print.c
        include/dns_print.h
        src/rbtree.c
        include/rbtree.h
        src/cache.c
        include/cache.h
        src/query_pool.c
        include/query_pool.h)
target_link_libraries(main uv)