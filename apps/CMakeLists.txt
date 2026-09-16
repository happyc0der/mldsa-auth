# Step 6 reference transport (spec §6.5): socket I/O, framing, connection
# logic and demo-only key files, shared by the two apps and tests/test_net.c.
add_library(mldsa_demo STATIC
  net_io.c
  frame.c
  demo_app.c
  demo_keys.c
)
target_include_directories(mldsa_demo PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(mldsa_demo PUBLIC mldsa_core)
target_compile_options(mldsa_demo PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(mldsa_demo PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(mldsa_demo PUBLIC ${MLDSA_SANITIZE_FLAGS})

add_executable(auth_server auth_server.c)
target_link_libraries(auth_server PRIVATE mldsa_demo)
target_compile_options(auth_server PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(auth_server PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(auth_server PRIVATE ${MLDSA_SANITIZE_FLAGS})

add_executable(auth_client auth_client.c)
target_link_libraries(auth_client PRIVATE mldsa_demo)
target_compile_options(auth_client PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(auth_client PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(auth_client PRIVATE ${MLDSA_SANITIZE_FLAGS})

# The authentication daemon subsystem (V4-6+).
add_subdirectory(authd)
