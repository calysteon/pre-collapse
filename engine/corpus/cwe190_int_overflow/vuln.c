/* CWE-190: Integer overflow leading to an undersized allocation.
 *
 * An element count is read from the input and multiplied by the element width to size
 * an allocation. The product overflows size_t and wraps to a small value, so malloc
 * returns a tiny buffer -- then the loop writes `count` elements far past its end.
 *
 * Donor patch for this class: checked_alloc_multiply (see precollapse/patch.py).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void handle(const unsigned char *in, size_t n) {
    if (n < 8) return;
    size_t count = 0;
    for (int i = 0; i < 8; i++) count |= (size_t)in[i] << (8 * i);
    const size_t width = sizeof(size_t);

    size_t *arr = (size_t *)malloc(count * width);   /* <-- count*width overflows size_t */
    if (!arr) return;
    for (size_t i = 0; i < count; i++) arr[i] = i;   /* writes `count` elements */
    free(arr);
}

int main(void) {
    static unsigned char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    handle(buf, n);
    return 0;
}
