set(NAME client)
add_executable(${NAME}
    main.c
)
target_link_libraries(${NAME}
    ${OPENSSL_LIBRARIES}
)