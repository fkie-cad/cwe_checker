#include <string.h>
#include <stdlib.h>

void constant_system() {
    system("ls");
}

int main(int argc, char **argv) {
    char dest[30] = "usr/bin/cat ";
    strcat(dest, argv[1]);
    system(dest);
    constant_system();
    return 0;
}
