/* CWE-416: Use-after-free.
 *
 * A "reset" opcode frees the working buffer on one path. A later path reuses the
 * buffer, guarding with `if (buf)` -- but the pointer is never cleared at the free,
 * so the guard passes and the code writes through a dangling pointer.
 *
 * Donor patch for this class: null_after_free (see precollapse/patch.py).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void handle(const unsigned char *in, size_t n) {
    char *buf = (char *)malloc(32);
    if (!buf) return;
    memcpy(buf, in, n < 32 ? n : 32);

    if (n >= 1 && in[0] == 0xFF) {   /* "reset" opcode frees the buffer */
        free(buf);
    }
    if (buf) {                       /* <-- ineffective guard: buf still dangles after reset */
        buf[0] = 0x41;               /* use-after-free write on the reset path */
        return;                      /* (non-reset path leaks; leak-check is off in the oracle) */
    }
}

int main(void) {
    static unsigned char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    handle(buf, n);
    return 0;
}
