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
        conn.h
        dictionary.h
        http.h)

set (SRCS
        log.c
        asnet.c
        alarm.c
        rbtree.c
        bufferpool.c
        conn.c
        dictionary.c
        http.c)

add_executable (httpsrv server.c ${HDRS} ${SRCS})
target_link_libraries (httpsrv ${CMAKE_THREAD_LIBS_INIT})
add_executable (httpcli client.c ${HDRS} ${SRCS})
target_link_libraries (httpcli ${CMAKE_THREAD_LIBS_INIT})
add_executable (test test.c ${HDRS} ${SRCS})
target_link_libraries (test ${CMAKE_THREAD_LIBS_INIT})
