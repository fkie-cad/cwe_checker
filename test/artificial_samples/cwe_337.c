
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]){
    srand(time(NULL));
    return rand();
}

