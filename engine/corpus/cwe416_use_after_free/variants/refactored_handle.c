/* Same class (CWE-416), refactored control flow (opcode switch instead of an if). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void run(const unsigned char *in, size_t n) {
    char *p = (char *)malloc(32);
    if (!p) return;
    memcpy(p, in, n < 32 ? n : 32);

    unsigned char op = (n >= 1) ? in[0] : 0;
    switch (op) {
        case 0xFF:                     /* "reset" opcode frees the buffer */
            free(p);
            break;
        default:
            break;
    }
    if (p) {                           /* ineffective guard: p still dangles after reset */
        p[0] = 0x41;                   /* use-after-free write on the reset path */
        return;
    }
}

int main(void) {
    static unsigned char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    run(buf, n);
    return 0;
}
