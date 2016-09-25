set(NAME server)
add_executable(${NAME}
    main.c
)
target_link_libraries(${NAME}
    common
    ${CMAKE_THREAD_LIBS_INIT}
    ${OPENSSL_LIBRARIES}
)