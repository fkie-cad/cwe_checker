#include <stdio.h>
#include <stdbool.h>

void integer_underflow_subtraction(){
        int i;
        i = -2147483648;
        i = i - 1;
        printf("[integer_overflow_subtraction] %d\n", i);
}



int main (void)
{
        integer_underflow_subtraction();
}
