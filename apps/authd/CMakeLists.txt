# The authentication daemon (V4-6 onward). keyfile.c is the MLDSAEK1 key
# envelope; later steps add the store, the event loop and the local API.
add_library(mldsa_authd STATIC
  keyfile.c
  authd_secret.c
  memlock.c
  store/store.c
  authd_config.c
  base32.c
  recovery.c
  sha1.c
  ws.c
  proxy_v2.c
  ratelimit.c
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
target_link_options(mldsa_authd PUBLIC ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})

# The daemon binary.
add_executable(mldsa_authd_bin authd_main.c)
set_target_properties(mldsa_authd_bin PROPERTIES OUTPUT_NAME mldsa-authd)
target_link_libraries(mldsa_authd_bin PRIVATE mldsa_authd)
target_compile_options(mldsa_authd_bin PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(mldsa_authd_bin PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(mldsa_authd_bin PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})

# The two command-line tools (V4-9b, spec 13). Both are thin main()s over
# authd_cli.c, which is in the library so tests can call the subcommands
# directly. authd_client.c lives in apps/ rather than apps/authd/ because it is
# the DEVICE's tool, not part of the daemon.
add_executable(authd_admin_bin authd_admin.c)
set_target_properties(authd_admin_bin PROPERTIES OUTPUT_NAME authd_admin)
target_link_libraries(authd_admin_bin PRIVATE mldsa_authd)
target_compile_options(authd_admin_bin PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(authd_admin_bin PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(authd_admin_bin PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})

add_executable(authd_client_bin ${CMAKE_CURRENT_SOURCE_DIR}/../authd_client.c)
set_target_properties(authd_client_bin PROPERTIES OUTPUT_NAME authd_client)
target_link_libraries(authd_client_bin PRIVATE mldsa_authd)
target_compile_options(authd_client_bin PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(authd_client_bin PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(authd_client_bin PRIVATE ${MLDSA_SANITIZE_FLAGS} ${MLDSA_HARDENING_LINK_FLAGS})

# --- installation (V4-11, audit finding F7) -------------------------------
# The three binaries a deployment actually runs, and the two files an operator
# copies. Nothing else is installed: the static libraries are build artefacts
# of this project, not a C API anyone is invited to link against, and shipping
# headers would imply a stability promise no step has made.
#
# The install tree is also what `tools/audit/check_hardening.sh --require`
# gates in CI, because it contains exactly what ships -- gating the whole build
# directory would additionally judge test and benchmark binaries that nobody
# deploys, and a gate whose scope is wider than its claim invites exceptions.
#
# EVERY RULE CARRIES `COMPONENT mldsa-authd`, and the documented command passes
# `--component mldsa-authd`. That is not bureaucracy: liboqs is brought in with
# FetchContent and defines its own install() rules, so a bare
# `cmake --install` also deposits a static liboqs.a, its headers and its CMake
# package files into the prefix -- a vendored, pin-locked, `-march`-tuned
# liboqs sitting in /usr/local/lib where some *other* build on that host can
# find it and link against it. Naming a component leaves those rules in the
# default "Unspecified" component, which `--component` does not run.
#
# `EXCLUDE_FROM_ALL` on FetchContent_Declare would be the tidier fix and is
# not available here: it arrived in CMake 3.28 and this project's floor is
# 3.20 (top-level CMakeLists.txt:1). Raising the floor to suppress a
# dependency's install rules would be the tail wagging the dog.
include(GNUInstallDirs)
install(TARGETS mldsa_authd_bin authd_admin_bin authd_client_bin
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT mldsa-authd)
install(FILES
          ${CMAKE_SOURCE_DIR}/deploy/mldsa-authd.service
          ${CMAKE_SOURCE_DIR}/deploy/authd.conf.example
          ${CMAKE_SOURCE_DIR}/deploy/Caddyfile.example
        DESTINATION ${CMAKE_INSTALL_DATADIR}/mldsa-authd
        COMPONENT mldsa-authd)
