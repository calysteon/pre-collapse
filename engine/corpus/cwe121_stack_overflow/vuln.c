/* CWE-121: Stack-based buffer overflow.
 *
 * The classic shape: attacker-controlled bytes are copied into a fixed-size stack
 * buffer with an unbounded copy. Any input of length >= sizeof(name) walks off the
 * end of the frame. This is the same defect class as countless real CVEs; here it is
 * isolated so the sanitizer verdict is unambiguous.
 *
 * Donor patch for this class: bounded_string_copy (see precollapse/patch.py).
 */
#include <stdio.h>
#include <string.h>

static int handle(const char *input) {
    char name[16];
    strcpy(name, input);          /* <-- unbounded copy: overflows when strlen(input) >= 16 */
    return (int)strlen(name);
}

int main(void) {
    static char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
    buf[n] = '\0';
    volatile int r = handle(buf);
    (void)r;
    return 0;
}
