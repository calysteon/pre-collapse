/* Same class (CWE-121), refactored control flow and a differently sized buffer.
 * The unbounded copy sits in the same scope as the destination array, so the class
 * donor patch (snprintf with sizeof(dst)) is exactly right here too. */
#include <stdio.h>
#include <string.h>

static int consume(const char *payload) {
    char field[24];
    int i = 0;
    do {
        strcpy(field, payload);        /* unbounded copy into fixed stack buffer */
        i++;
    } while (i < 1);
    return (int)strlen(field);
}

int main(void) {
    static char data[8192];
    size_t n = fread(data, 1, sizeof(data) - 1, stdin);
    data[n] = '\0';
    volatile int r = consume(data);
    (void)r;
    return 0;
}
