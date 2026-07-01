#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    unsigned char buf[2] = {0, 0};
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    if (n < sizeof(buf)) return 0;

    unsigned int b0 = buf[0];
    unsigned int b1 = buf[1];
    if (((b0 ^ 0x5aU) | (b1 ^ 0x21U)) == 0) abort();
    return 0;
}
