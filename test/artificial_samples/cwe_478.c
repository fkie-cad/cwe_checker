#include <stdio.h>
#include <stdlib.h>


#define FAILED 0
#define PASSED 1

int main(int argc, char *argv[argc])
{
srand(42);
int result = rand() % 2;

switch (result) {
case FAILED:
        printf("Security check failed!\n");
        exit(-1);
        //Break never reached because of exit()
        break;
case PASSED:
        printf("Security check passed.\n");
        break;
}

        return 0;
}
