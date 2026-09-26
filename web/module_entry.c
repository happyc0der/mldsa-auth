/* The ES module's translation unit (V4-13b). Emscripten links an executable
 * target, and every export lives in mldsa_client_wasm; this file only gives
 * the link a unit of its own. There is no main(): the module is a library,
 * initialised by the caller's ccw_init(). */
#include "client_wasm.h"

/* Referenced so the shim's archive member is always pulled into the link. */
void *const mldsa_client_module_anchor = (void *)&ccw_init;
