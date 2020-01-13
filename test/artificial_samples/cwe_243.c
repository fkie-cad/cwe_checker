#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>

void chroot_fail(){
  chdir("/tmp");
  if (chroot("/tmp") != 0) {
    perror("chroot /tmp");
  }
}

int main(void) {
  chroot_fail();
}
