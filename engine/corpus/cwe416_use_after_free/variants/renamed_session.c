/* Same class (CWE-416), renamed identifiers. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void session_op(const unsigned char *in, size_t n) {
    char *state = (char *)malloc(32);
    if (!state) return;
    memcpy(state, in, n < 32 ? n : 32);

    if (n >= 1 && in[0] == 0xFF) {     /* "reset" opcode frees the buffer */
        free(state);
    }
    if (state) {                       /* ineffective guard: state still dangles */
        state[0] = 0x41;               /* use-after-free write on the reset path */
        return;
    }
}

int main(void) {
    static unsigned char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    session_op(buf, n);
    return 0;
}
