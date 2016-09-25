cmake_minimum_required(VERSION 3.5)
add_definitions(-std=gnu99)
add_definitions(-Wall -Werror -Wpedantic)
find_package(OpenSSL REQUIRED)

add_subdirectory(client)
add_subdirectory(server)

set(NAME using_c_ssl)
add_executable(${NAME}
    main.c
)
target_link_libraries(${NAME}
    ${OPENSSL_LIBRARIES}
)
enable_testing()