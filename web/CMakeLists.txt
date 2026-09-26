# The browser module (V4-13b): mldsa_client.mjs + mldsa_client.wasm.
#
# An ES module factory (MODULARIZE + EXPORT_ES6) exporting exactly
# web/exports.txt, for the web and for Node (the interop test imports the SAME
# file a page will). Link choices, each for a reason a page will care about:
#   -sFILESYSTEM=0          a page has no filesystem; nothing here needs one
#   -sDYNAMIC_EXECUTION=0   no eval/new Function: a strict CSP can serve it
#   -sSTACK_SIZE=8MB, -sALLOW_MEMORY_GROWTH=1   V4-2 S6's stack; 64 MiB Argon2id
# tests/wasm_module_gates.mjs checks the export set and the size budget.
add_executable(mldsa_client_module module_entry.c)
set_target_properties(mldsa_client_module PROPERTIES OUTPUT_NAME mldsa_client SUFFIX ".mjs")
target_link_libraries(mldsa_client_module PRIVATE mldsa_client_wasm)
target_compile_options(mldsa_client_module PRIVATE ${MLDSA_HARDENING_FLAGS})
file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/exports.txt _mldsa_exports REGEX "^_")
list(JOIN _mldsa_exports "," _mldsa_exports_csv)
target_link_options(mldsa_client_module PRIVATE
  ${MLDSA_WASM_LINK_FLAGS}
  -sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORT_NAME=createMldsaClient
  -sENVIRONMENT=web,worker,node
  -sFILESYSTEM=0 -sDYNAMIC_EXECUTION=0
  "-sEXPORTED_FUNCTIONS=${_mldsa_exports_csv}"
  "-sEXPORTED_RUNTIME_METHODS=HEAPU8,HEAPU32,HEAPF64,UTF8ToString")
set_property(TARGET mldsa_client_module APPEND PROPERTY LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/exports.txt)

add_test(NAME wasm_module_gates
         COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} ${PROJECT_SOURCE_DIR}/tests/wasm_module_gates.mjs
                 $<TARGET_FILE_DIR:mldsa_client_module>/mldsa_client.wasm
                 $<TARGET_FILE:mldsa_client_module>
                 ${CMAKE_CURRENT_SOURCE_DIR}/exports.txt)
