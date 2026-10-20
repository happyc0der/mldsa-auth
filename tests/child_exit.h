/* How a forked test child leaves (V4-40, audit F5).
 *
 * A child leaves with _exit(), never exit(), so it runs none of the parent's
 * atexit handlers and flushes none of the parent's stdio a second time. That
 * also skips the hook a coverage build writes its profile from, so before
 * V4-40 everything a child ran counted as never run: the prompt the pty test
 * drives, the CLI test_authd_cli runs pumped, the demo server and proxy of
 * test_net. In an MLDSA_COVERAGE build the profile is written first; in every
 * other build this is _exit() and nothing else. */
#ifndef MLDSA_TESTS_CHILD_EXIT_H
#define MLDSA_TESTS_CHILD_EXIT_H

#include <unistd.h>

#ifdef MLDSA_COVERAGE
int __llvm_profile_write_file(void); /* compiler-rt's profile runtime */
#endif

__attribute__((noreturn)) static inline void child_exit(int rc)
{
#ifdef MLDSA_COVERAGE
    (void)__llvm_profile_write_file();
#endif
    _exit(rc);
}

#endif
