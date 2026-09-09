add_library(mldsa_core STATIC
  crypto/mldsa_wrap.c
  crypto/kex.c
  crypto/aead.c
  protocol/handshake.c
  protocol/session.c
  protocol/transcript.c
  protocol/keystore.c
  util/secure_mem.c
  util/wire_int.c
)

target_include_directories(mldsa_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol
  ${CMAKE_CURRENT_SOURCE_DIR}/util
)

target_link_libraries(mldsa_core PUBLIC oqs sodium)

target_compile_options(mldsa_core PRIVATE ${MLDSA_HARDENING_FLAGS} ${MLDSA_SANITIZE_FLAGS})
target_compile_definitions(mldsa_core PRIVATE ${MLDSA_HARDENING_DEFS})
target_link_options(mldsa_core PUBLIC ${MLDSA_SANITIZE_FLAGS})
