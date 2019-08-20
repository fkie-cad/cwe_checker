#include <stdio.h>
#include <stdlib.h>

void simple_check_path(){
             // read in integer
        int myInt;
        scanf("%d", &myInt);

        // provoke integer overflow
        void *m = malloc(myInt * 8);

        // free data
        if (m != NULL)
                free(m);
}

int main(void)
{
        simple_check_path();
        return 0;
}
