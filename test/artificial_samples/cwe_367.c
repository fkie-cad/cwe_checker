#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(){

  if (access("file", W_OK) != 0) {
    exit(1);
  }

  char* buffer = malloc(6);
  if(buffer == NULL){
    exit(1);
  }
  memset(buffer, 1, 6);
  
  int fd = open("file", O_WRONLY);
  write(fd, buffer, sizeof(buffer));

  close(fd);
  free(buffer);
}
