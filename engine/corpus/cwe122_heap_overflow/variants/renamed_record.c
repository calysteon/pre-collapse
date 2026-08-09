/* Same class (CWE-122), renamed identifiers. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void parse_record(const unsigned char *data, size_t len) {
    size_t want = (len >= 1) ? data[0] : 0;
    const unsigned char *body = data + 1;
    size_t have = (len >= 1) ? len - 1 : 0;
    size_t take = want < have ? want : have;

    char *slot = (char *)malloc(16);
    if (!slot) return;
    memcpy(slot, body, take);          /* overflows slot when take > 16 */
    volatile char sink = slot[0];
    (void)sink;
    free(slot);
}

int main(void) {
    static unsigned char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    parse_record(buf, n);
    return 0;
}
