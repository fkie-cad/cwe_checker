#include <stdlib.h>
#include <stdio.h>

void set_array_elements(int* array) {
    for(int i = 0; i<= 10; i++) {
        array[i] = i*i; // Out-of-bounds write for arrays that are too small.
    }
}

void print_array_sum(int* array) {
    int sum = 0;
    for(int i = 0; i<= 10; i++) {
        sum += array[i]; // Out-of-bounds read for arrays that are too small.
    }
    printf("%d\n", sum);
}

int main() {
    int* array = calloc(5, sizeof(int));
    set_array_elements(array);
    free(array);

    array = malloc(5 * sizeof(int));
    print_array_sum(array);

    puts((void*) array - 1); // Parameter is an out-of-bounds pointer.
    free(array);
}