#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void umask_incorrect(){
        umask(0666);
        int fd = open("some_random_file", O_CREAT|O_WRONLY, 0666);
        close(fd);
}

void umask_correct(){
        umask(022);
        int fd = open("some_random_file", O_CREAT|O_WRONLY, 0666);
        close(fd);
}

int main(){
        umask_correct();
        umask_incorrect();
        return 0;
}
