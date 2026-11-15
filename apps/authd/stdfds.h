#ifndef AUTHD_STDFDS_H
#define AUTHD_STDFDS_H

/* Descriptors 0, 1 and 2 at process start (V4-201, F280).
 *
 * A process can be started with any of them closed (`cmd >&-`, a careless
 * parent). The next open() or socket() then returns that number, and
 * everything written to "standard output" or "standard error" goes into
 * whatever it is: on Linux `authd_client login >&-` printed the login code
 * into its own connection to the daemon and exited 0, and a daemon started
 * with standard error closed would write its log lines into the first file
 * it opened for writing -- its store.
 *
 * stdfds_ensure_open() gives every closed one of the three /dev/null (read
 * for 0, write for 1 and 2), so no later descriptor can take its number. It
 * must be the first thing main() does.
 *
 * Returns a bit mask of the descriptors that were closed (bit n for
 * descriptor n), or -1 if one could not be opened. */
#define STDFDS_STDIN_WAS_CLOSED  1
#define STDFDS_STDOUT_WAS_CLOSED 2
#define STDFDS_STDERR_WAS_CLOSED 4

int stdfds_ensure_open(void);

#endif
