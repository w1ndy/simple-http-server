cmake_minimum_required (VERSION 2.7)
project (httpsrv)

find_package (Threads)

set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set (HDRS
        log.h
        asnet.h
        alarm.h
        rbtree.h
        bufferpool.h
        conn.h)

set (SRCS
        main.c
        log.c
        asnet.c
        alarm.c
        rbtree.c
        bufferpool.c
        conn.c)

add_executable (httpsrv ${HDRS} ${SRCS})
target_link_libraries (httpsrv ${CMAKE_THREAD_LIBS_INIT})
