#include <stdio.h>
#include <stdlib.h>

void simple_check_path_in_function(){
        // read in integer
        int myInt;
        scanf("%d", &myInt);

        // provoke integer overflow
        void *m = malloc(myInt * 8);

        // free data
        if (m != NULL)
                free(m);
}

int read_int(){
        int myInt;
        scanf("%d", &myInt);
        return myInt;
}

void check_path_across_functions(){
        int i = read_int();

        // provoke integer overflow
        void *m = malloc(i * 8);

        // free data
        if (m != NULL)
                free(m);
}

int main(void)
{
        simple_check_path_in_function();
        check_path_across_functions();
        return 0;
}
