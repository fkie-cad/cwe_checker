#include <stdlib.h>
#include <stdio.h>

void uninitalized_variable(){
        int a; // never initialized
        int b = 7;
        int c = a + b;
        printf("a is %d, b is %d, c is %d\n", a , b, c);
}

int main(int argc, char *argv[argc])
{
        uninitalized_variable();
        return 0;
}
