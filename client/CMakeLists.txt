set(NAME client)
add_executable(${NAME}
    main.c
)
target_link_libraries(${NAME}
    common
    ${OPENSSL_LIBRARIES}
)