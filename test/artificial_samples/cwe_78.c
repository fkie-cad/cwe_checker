#include <string.h>
#include <stdlib.h>

int constant_system() {
    system("ls");
}

int main(int argc, char **argv) {
    char *dest = "usr/bin/cat ";
    strcat(dest, argv[1]);
    system(dest);
    constant_system();
    return 0;
}
