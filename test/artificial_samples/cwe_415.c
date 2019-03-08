
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE1 512

void bla(){
        char *buf1R1;
        char *buf2R1;
        buf1R1 = (char *) malloc(BUFSIZE1);
        buf2R1 = (char *) malloc(BUFSIZE1);
        free(buf1R1);
        free(buf2R1);
        free(buf1R1);
}

int main(int argc, char **argv) {
char *buf1R1;
char *buf2R1;
buf1R1 = (char *) malloc(BUFSIZE1);
buf2R1 = (char *) malloc(BUFSIZE1);
free(buf1R1);
free(buf2R1);
free(buf1R1);
bla();
}
