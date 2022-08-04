#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]){
	char buff[0xF4250]; // dec: 1000016
	malloc(0xF4250);

	return 0;
}