/* Same class (CWE-190), renamed identifiers. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void alloc_table(const unsigned char *in, size_t n) {
    if (n < 8) return;
    size_t rows = 0;
    for (int i = 0; i < 8; i++) rows |= (size_t)in[i] << (8 * i);
    const size_t width = sizeof(size_t);

    size_t *table = (size_t *)malloc(rows * width);   /* rows*width overflows size_t */
    if (!table) return;
    for (size_t i = 0; i < rows; i++) table[i] = i;
    free(table);
}

int main(void) {
    static unsigned char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    alloc_table(buf, n);
    return 0;
}
