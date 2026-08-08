/* CWE-122: Heap-based buffer overflow.
 *
 * A fixed-size record is allocated on the heap, then a length byte taken from the
 * input governs a copy into it with no check against the allocation size. A declared
 * length larger than the record walks off the end of the heap chunk.
 *
 * Donor patch for this class: clamp_heap_copy (see precollapse/patch.py).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void handle(const unsigned char *in, size_t n) {
    size_t claimed = (n >= 1) ? in[0] : 0;       /* attacker-declared length 0..255 */
    const unsigned char *payload = in + 1;
    size_t avail = (n >= 1) ? n - 1 : 0;
    size_t copy = claimed < avail ? claimed : avail;

    char *rec = (char *)malloc(16);              /* 16-byte record */
    if (!rec) return;
    memcpy(rec, payload, copy);                  /* <-- overflows rec when copy > 16 */
    volatile char sink = rec[0];
    (void)sink;
    free(rec);
}

int main(void) {
    static unsigned char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    handle(buf, n);
    return 0;
}
