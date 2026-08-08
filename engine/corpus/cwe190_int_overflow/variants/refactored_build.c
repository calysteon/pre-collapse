/* Same class (CWE-190), refactored: element count parsed in a helper. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t read_count(const unsigned char *in) {
    size_t v = 0;
    for (int i = 0; i < 8; i++) v |= (size_t)in[i] << (8 * i);
    return v;
}

static void build(const unsigned char *in, size_t n) {
    if (n < 8) return;
    size_t elems = read_count(in);
    size_t unit = sizeof(size_t);

    size_t *arr = (size_t *)malloc(elems * unit);     /* elems*unit overflows size_t */
    if (!arr) return;
    for (size_t j = 0; j < elems; j++) arr[j] = j;
    free(arr);
}

int main(void) {
    static unsigned char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    build(buf, n);
    return 0;
}
