# The authentication daemon (V4-6 onward). keyfile.c is the MLDSAEK1 key
# envelope; later steps add the store, the event loop and the local API.
add_library(mldsa_authd STATIC
  keyfile.c
)
target_include_directories(mldsa_authd PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(mldsa_authd PUBLIC mldsa_demo)
target_compile_options(mldsa_authd PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(mldsa_authd PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(mldsa_authd PUBLIC ${MLDSA_SANITIZE_FLAGS})
