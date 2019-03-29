#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE1 10

int main(int argc, char **argv) {
        char buf1R1[BUFSIZE1];
        for(int i = 0; i < BUFSIZE1 + 10; i++){
                buf1R1[i] = 'A';
        }
        memset(&buf1R1, 0x42, 26);
}
