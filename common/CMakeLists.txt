set(NAME common)
add_library(${NAME}
    src/common.c
)
target_link_libraries(${NAME}
    ${OPENSSL_LIBRARIES}
)