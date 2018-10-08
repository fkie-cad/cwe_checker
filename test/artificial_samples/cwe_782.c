#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[argc])
{

        int fd = open("/dev/my_driver", O_WRONLY, O_NONBLOCK);
        if (fd == -1){
                printf("Could not open my_driver.\n");
                exit(1);
        }

        if (ioctl(fd, 0x42) == -1){
                printf("ioctl failed.\n");
        }

        if (close(fd) == -1){
                printf("Could not properly close my_driver.\n");
                exit(1);
        }

        return 0;
}
