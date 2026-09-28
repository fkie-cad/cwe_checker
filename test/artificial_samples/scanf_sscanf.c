#include <stdio.h>
#include <stdlib.h>

// Regression test sample: calls to (s)scanf must not crash the pcode-to-IR
// translation, e.g., on architectures where the parameter registers of the
// calling convention are not known.

int main(int argc, char **argv) {
    char cmd[64];
    int number;
    scanf("%d", &number);
    sscanf(argv[1], "%63s", cmd);
    system(cmd);
    return number;
}
