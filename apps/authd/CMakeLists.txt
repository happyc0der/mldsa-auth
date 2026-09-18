# The authentication daemon (V4-6 onward). keyfile.c is the MLDSAEK1 key
# envelope; later steps add the store, the event loop and the local API.
add_library(mldsa_authd STATIC
  keyfile.c
  authd_secret.c
  store/store.c
  authd_config.c
  base32.c
  recovery.c
  authmsg.c
  tokens.c
  localapi.c
  localcli.c
  authd_cli.c
  authd_conn.c
  conn_io.c
  evloop.c
  listener.c
  authd_log.c
)
target_include_directories(mldsa_authd PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/store)
# sqlite3 is PRIVATE: the store's API is pure C types, so no consumer of
# mldsa_authd needs sqlite3.h on its include path.
target_link_libraries(mldsa_authd PUBLIC mldsa_demo PRIVATE sqlite3)
target_compile_options(mldsa_authd PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(mldsa_authd PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(mldsa_authd PUBLIC ${MLDSA_SANITIZE_FLAGS})

# The daemon binary. V4-8a is the transport skeleton: it validates config,
# listens, accepts, reassembles frames and drains on SIGTERM, but does not yet
# speak the protocol (V4-8b).
add_executable(mldsa_authd_bin authd_main.c)
set_target_properties(mldsa_authd_bin PROPERTIES OUTPUT_NAME mldsa-authd)
target_link_libraries(mldsa_authd_bin PRIVATE mldsa_authd)
target_compile_options(mldsa_authd_bin PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(mldsa_authd_bin PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(mldsa_authd_bin PRIVATE ${MLDSA_SANITIZE_FLAGS})

# The two command-line tools (V4-9b, spec 13). Both are thin main()s over
# authd_cli.c, which is in the library so tests can call the subcommands
# directly. authd_client.c lives in apps/ rather than apps/authd/ because it is
# the DEVICE's tool, not part of the daemon.
add_executable(authd_admin_bin authd_admin.c)
set_target_properties(authd_admin_bin PROPERTIES OUTPUT_NAME authd_admin)
target_link_libraries(authd_admin_bin PRIVATE mldsa_authd)
target_compile_options(authd_admin_bin PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(authd_admin_bin PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(authd_admin_bin PRIVATE ${MLDSA_SANITIZE_FLAGS})

add_executable(authd_client_bin ${CMAKE_CURRENT_SOURCE_DIR}/../authd_client.c)
set_target_properties(authd_client_bin PROPERTIES OUTPUT_NAME authd_client)
target_link_libraries(authd_client_bin PRIVATE mldsa_authd)
target_compile_options(authd_client_bin PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(authd_client_bin PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(authd_client_bin PRIVATE ${MLDSA_SANITIZE_FLAGS})
