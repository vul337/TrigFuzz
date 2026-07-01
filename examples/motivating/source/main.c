/*
 * The motivating example from Listing 1 of the TrigFuzz paper:
 * a use-of-uninitialised-variable bug triggered when sscanf fails to
 * populate at least two integers from the dotted-decimal input.
 *
 * Feeds stdin through sscanf("%d.%d.%d.%d") and then uses `b`.  If the
 * input does not contain at least one '.' separator, `b` is never
 * written and the call to use(b) is the bug.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static volatile int sink;
static void use(int x) { sink ^= x; }

int main(void) {
    char line[256] = {0};
    if (fread(line, 1, sizeof(line) - 1, stdin) <= 0) return 0;

    int a, b, c, d;
    int v = sscanf(line, "%d.%d.%d.%d", &a, &b, &c, &d);
    use(b);  /* <- TCU loc; triggers when v < 2 */
    if (v < 2) {
        /* Simulate a fault so the fuzzer sees a non-zero exit.
         * A real PUT compiled under ASan would abort on read-of-uninit. */
        abort();
    }
    return 0;
}
