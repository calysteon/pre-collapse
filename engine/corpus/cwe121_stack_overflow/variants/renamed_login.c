/* Same class (CWE-121), renamed identifiers, extra wrapper indirection.
 * A syntactic clone of the stack-overflow idiom: no shared variable names with the
 * canonical vuln.c, yet the same pre-collapse signature and the same donor patch. */
#include <stdio.h>
#include <string.h>

static int store_account(const char *credential) {
    char account[16];
    strcpy(account, credential);       /* unbounded copy into fixed stack buffer */
    return (int)strlen(account);
}

static int authenticate(const char *supplied) {
    return store_account(supplied);
}

int main(void) {
    static char line[8192];
    size_t n = fread(line, 1, sizeof(line) - 1, stdin);
    line[n] = '\0';
    volatile int r = authenticate(line);
    (void)r;
    return 0;
}
