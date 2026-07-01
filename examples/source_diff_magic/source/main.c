#include <stdio.h>
#include <stdlib.h>

int main(void) {
    unsigned char buf[4] = {0};
    if (fread(buf, 1, sizeof(buf), stdin) != sizeof(buf)) return 0;

    unsigned int v = buf[0];
    if (v == 89 && buf[1] == 'M' && buf[2] == 'A' && buf[3] == 'G') abort();
    return 0;
}
