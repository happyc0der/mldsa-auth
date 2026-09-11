# S24 -- Gate 2 of the approved Step 5 plan: a portable structural proof that
# the session hot path cannot allocate. Run by CTest as
#
#   cmake -DSESSION_C=<path/to/src/protocol/session.c> -P check_session_no_alloc.cmake
#
# Whole-file rules for session.c:
#   - no #include <stdlib.h>, <malloc.h> or <malloc/malloc.h>;
#   - no call to any ordinary or libsodium allocator (FORBIDDEN below);
#   - secure_mem_alloc called exactly once, inside session_init_from_handshake;
#   - secure_mem_free called exactly once, inside session_wipe.
# Hot-path region rules:
#   - exactly one "BEGIN STEADY-STATE: NO ALLOCATION" / "END STEADY-STATE"
#     marker pair, in that order;
#   - session_seal, session_open, session_rekey_due and
#     session_is_peer_confirmed are all defined inside it (with every static
#     helper they call -- anything outside would have to be one of the two
#     permitted allocation sites, which the counts above rule out);
#   - session_init_from_handshake and session_wipe are defined outside it;
#   - no allocator of any kind, secure_mem_alloc/free included, inside it.
#
# Built-in negative controls: before the real file is judged, the same rules
# are run on two mutated copies of it -- one with a malloc() call injected
# into the region, one with the END marker moved above session_open -- and
# the script fails unless BOTH are rejected. A scanner that accepts
# everything cannot pass.

cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED SESSION_C)
  message(FATAL_ERROR "usage: cmake -DSESSION_C=<path/to/session.c> -P check_session_no_alloc.cmake")
endif()
file(READ "${SESSION_C}" real_text)

set(BEGIN_MARK "/* BEGIN STEADY-STATE: NO ALLOCATION */")
set(END_MARK "/* END STEADY-STATE */")
set(FORBIDDEN malloc calloc realloc free aligned_alloc posix_memalign strdup strndup alloca mmap
              sodium_malloc sodium_allocarray sodium_free)
set(HOT_FUNCTIONS session_seal session_open session_rekey_due session_is_peer_confirmed)

# Number of call sites of `name` (word-bounded, so secure_mem_free never
# counts as free).
function(count_calls text name out)
  string(REGEX MATCHALL "[^A-Za-z0-9_]${name}[ \t]*\\(" hits "${text}")
  list(LENGTH hits n)
  set(${out} ${n} PARENT_SCOPE)
endfunction()

# Number of occurrences of a literal substring.
function(count_literal text needle out)
  string(LENGTH "${text}" full)
  string(REPLACE "${needle}" "" stripped "${text}")
  string(LENGTH "${stripped}" rest)
  string(LENGTH "${needle}" nlen)
  math(EXPR n "(${full} - ${rest}) / ${nlen}")
  set(${out} ${n} PARENT_SCOPE)
endfunction()

# Body of the function whose definition starts with `signature_prefix`, up to
# its closing brace at column 0. Empty if the definition is absent.
function(function_body text signature_prefix out)
  string(FIND "${text}" "\n${signature_prefix}" start)
  if(start EQUAL -1)
    set(${out} "" PARENT_SCOPE)
    return()
  endif()
  string(SUBSTRING "${text}" ${start} -1 tail)
  string(FIND "${tail}" "\n}\n" end)
  if(end EQUAL -1)
    set(${out} "" PARENT_SCOPE)
    return()
  endif()
  string(SUBSTRING "${tail}" 0 ${end} body)
  set(${out} "${body}" PARENT_SCOPE)
endfunction()

# Applies every rule to `text`; sets `out` to the list of violations (empty
# means the text passes).
function(check_text text out)
  set(r "")

  if(text MATCHES "#[ \t]*include[ \t]*<(stdlib|malloc|malloc/malloc)\\.h>")
    list(APPEND r "includes an allocation header (${CMAKE_MATCH_1}.h)")
  endif()

  foreach(fn IN LISTS FORBIDDEN)
    count_calls("${text}" ${fn} n)
    if(n GREATER 0)
      list(APPEND r "calls ${fn}() ${n} time(s)")
    endif()
  endforeach()

  count_calls("${text}" secure_mem_alloc n_alloc)
  count_calls("${text}" secure_mem_free n_free)
  if(NOT n_alloc EQUAL 1)
    list(APPEND r "secure_mem_alloc() called ${n_alloc} times (must be exactly 1)")
  endif()
  if(NOT n_free EQUAL 1)
    list(APPEND r "secure_mem_free() called ${n_free} times (must be exactly 1)")
  endif()

  function_body("${text}" "session_status_t session_init_from_handshake(" init_body)
  count_calls("${init_body}" secure_mem_alloc n)
  if(NOT n EQUAL 1)
    list(APPEND r "the one secure_mem_alloc() is not inside session_init_from_handshake")
  endif()
  function_body("${text}" "void session_wipe(" wipe_body)
  count_calls("${wipe_body}" secure_mem_free n)
  if(NOT n EQUAL 1)
    list(APPEND r "the one secure_mem_free() is not inside session_wipe")
  endif()

  count_literal("${text}" "${BEGIN_MARK}" n_begin)
  count_literal("${text}" "${END_MARK}" n_end)
  if(NOT n_begin EQUAL 1 OR NOT n_end EQUAL 1)
    list(APPEND r "expected exactly one BEGIN/END steady-state marker pair (found ${n_begin}/${n_end})")
  else()
    string(FIND "${text}" "${BEGIN_MARK}" p_begin)
    string(FIND "${text}" "${END_MARK}" p_end)
    if(p_end LESS p_begin)
      list(APPEND r "END marker precedes BEGIN marker")
    else()
      string(LENGTH "${BEGIN_MARK}" blen)
      math(EXPR region_start "${p_begin} + ${blen}")
      math(EXPR region_len "${p_end} - ${region_start}")
      string(SUBSTRING "${text}" ${region_start} ${region_len} region)
      string(SUBSTRING "${text}" 0 ${p_begin} before)
      string(SUBSTRING "${text}" ${p_end} -1 after)
      set(outside "${before}${after}")

      foreach(fn IN LISTS HOT_FUNCTIONS)
        if(NOT region MATCHES "\n(session_status_t|bool)[ \t]+${fn}\\(")
          list(APPEND r "hot-path function ${fn}() is not defined inside the steady-state region")
        endif()
      endforeach()
      foreach(fn session_init_from_handshake session_wipe)
        if(region MATCHES "\n(session_status_t|void)[ \t]+${fn}\\(" OR
           NOT outside MATCHES "\n(session_status_t|void)[ \t]+${fn}\\(")
          list(APPEND r "${fn}() must be defined outside the steady-state region")
        endif()
      endforeach()
      foreach(fn IN LISTS FORBIDDEN ITEMS secure_mem_alloc secure_mem_free)
        count_calls("${region}" ${fn} n)
        if(n GREATER 0)
          list(APPEND r "steady-state region calls ${fn}() ${n} time(s)")
        endif()
      endforeach()
    endif()
  endif()

  set(${out} "${r}" PARENT_SCOPE)
endfunction()

# --- Negative controls: the scanner must reject both mutated copies. -------
string(REPLACE "${END_MARK}"
       "static void injected_scratch(void) { void *p = malloc(16); (void)p; }\n${END_MARK}"
       control_inject "${real_text}")
check_text("${control_inject}" v1)
if(v1 STREQUAL "")
  message(FATAL_ERROR "NEGATIVE CONTROL 1 NOT REJECTED: malloc() injected into the steady-state "
                      "region was accepted -- the scanner is broken")
endif()
message(STATUS "negative control 1 (malloc injected into the region) rejected as required:")
foreach(v IN LISTS v1)
  message(STATUS "    - ${v}")
endforeach()

string(REPLACE "${END_MARK}" "" control_moved "${real_text}")
string(REPLACE "\nsession_status_t session_open(" "\n${END_MARK}\nsession_status_t session_open("
       control_moved "${control_moved}")
check_text("${control_moved}" v2)
if(v2 STREQUAL "")
  message(FATAL_ERROR "NEGATIVE CONTROL 2 NOT REJECTED: session_open() moved outside the region "
                      "was accepted -- the scanner is broken")
endif()
message(STATUS "negative control 2 (END marker moved above session_open) rejected as required:")
foreach(v IN LISTS v2)
  message(STATUS "    - ${v}")
endforeach()

# --- The real file. --------------------------------------------------------
check_text("${real_text}" violations)
if(NOT violations STREQUAL "")
  message(STATUS "session.c violates the no-allocation rules:")
  foreach(v IN LISTS violations)
    message(STATUS "    - ${v}")
  endforeach()
  message(FATAL_ERROR "session_no_alloc_scan FAILED: ${SESSION_C}")
endif()
message(STATUS "PASS: ${SESSION_C}: no allocation header or allocator call; exactly one "
               "secure_mem_alloc (in session_init_from_handshake) and one secure_mem_free "
               "(in session_wipe); session_seal, session_open, session_rekey_due and "
               "session_is_peer_confirmed are all inside the allocation-free region")
