/* A planted undefined behaviour (V4-24b, CLAIMS P8, audit F94): a signed
 * overflow on a value the compiler cannot fold. Built only into UBSan and
 * fuzz trees, with the project's sanitizer flags; the CTest ubsan_aborts
 * requires it to STOP. With -fsanitize=undefined but no
 * -fno-sanitize-recover, UBSan prints its report and the process goes on to
 * print the line below and exit 0 -- which is how a UB report once sat inside
 * a test that still passed. */
#include <limits.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    (void)argv;
    volatile int x = INT_MAX - 1 + argc;   /* INT_MAX when run with no arguments */
    const int y = x + 1;                   /* signed overflow */
    printf("ubsan-canary: survived the overflow (%d)\n", y);
    return 0;
}
