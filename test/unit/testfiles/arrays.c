#include <stdio.h>
#include <stdlib.h>

void heap_based_array(){
        char* a = malloc(20);

        for(int i=0; i<20;i++){
                *(a + i) = 'A';
        }

        free(a);
}

void stack_based_array(){
        char a[20];
        for(int i=0; i<20;i++){
                a[i] = 'A';
        }
}

int main(int argc, char *argv[argc])
{
        stack_based_array();
        heap_based_array();
        return 0;
}
