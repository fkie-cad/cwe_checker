#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE1 512

int main(int argc, char **argv) {
        char *buf1R1;
        char *buf2R1;
        buf1R1 = (char *) malloc(BUFSIZE1);
        buf2R1 = (char *) malloc(BUFSIZE1);
        free(buf1R1);
        free(buf2R1);
        memset(buf1R1, 0x42, BUFSIZE1);
}
