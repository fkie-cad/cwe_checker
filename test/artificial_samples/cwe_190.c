#import <stdio.h>
#import <stdlib.h>
#import <string.h>

#define png_t 4242

// example taken from the book
// "The Art of Software Security Assessment: Identifying and Preventing Software Vulnerabilities"
// slightly edited
char* make_table(unsigned int width, unsigned int height, char* init_row){
        unsigned int n;
        int i;
        char* buf;

        n = width * height;

        buf = (char*) malloc(n);
        if (!buf)
                return NULL;

        for(i=0; i < height; i++){
                memcpy(&buf[i* width], init_row, width);
        }

        return buf;
}

void tassa1(int arg1, int arg2){
        char init_row[] = "init";
        char *res = make_table(arg1, arg2, &init_row);
        printf("Table at %p\n", res);
        free(res);
}

int malloc_overflow_get_num_elems(){
        srand(42);
        return rand() * 1000000;
}


void malloc_overflow(){
        int num_elems = malloc_overflow_get_num_elems();
        void* ptr_elems = malloc(sizeof(png_t) * num_elems); // overflow occurs here
        printf("PNG at %p\n", ptr_elems);
        free(ptr_elems);
}

int packet_get_int(){
        return malloc_overflow_get_num_elems();
}

char* packet_get_string(){
        return NULL;
}

// taken from https://cwe.mitre.org/data/definitions/190.html
// slightly edited to make it compile
void overflow_ssh3_1(){
        char** response;
        int nresp = packet_get_int();
        if (nresp > 0) {
                response = malloc(nresp*sizeof(char*));
                for (int i = 0; i < nresp; i++)
                        response[i] = packet_get_string();
                free(response);
        }
}

int main(int argc, char *argv[argc])
{
        tassa1(atoi(argv[1]), atoi(argv[2]));
        malloc_overflow();
        overflow_ssh3_1();
        return 0;
}
