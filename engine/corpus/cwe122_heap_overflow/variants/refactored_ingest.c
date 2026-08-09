/* Same class (CWE-122), refactored: length is clamped to available input but never
 * to the allocation size, so an over-long declared length still overflows. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void ingest(const unsigned char *buf, size_t sz) {
    if (sz == 0) return;
    size_t k = buf[0];
    size_t avail = sz - 1;
    if (k > avail) k = avail;          /* clamped to input, NOT to the 16-byte area */
    char *area = (char *)malloc(16);   /* fixed 16-byte area */
    if (!area) return;
    memcpy(area, buf + 1, k);          /* overflows area when k > 16 */
    volatile char sink = area[0];
    (void)sink;
    free(area);
}

int main(void) {
    static unsigned char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    ingest(buf, n);
    return 0;
}
