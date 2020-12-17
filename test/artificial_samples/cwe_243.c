#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>

void chroot_fail(){
  chdir("/tmp");
  if (chroot("/tmp") != 0) {
    perror("chroot /tmp");
  }
}

// these are safe according to http://www.unixwiz.net/techtips/chroot-practices.html
void chroot_safe1(){
  chdir("/tmp");
  if (chroot("/tmp") != 0) {
    perror("chroot /tmp");
  }
  setuid(1077);
}

void chroot_safe2(){
  chdir("/tmp");
  if (chroot("/tmp") != 0) {
    perror("chroot /tmp");
  }
  setresuid(1077, 1077, 1077);
}

void chroot_safe3(){
  chdir("/tmp");
  if (chroot("/tmp") != 0) {
    perror("chroot /tmp");
  }
  setreuid(1077, 44);
}

void chroot_safe4(){
  chdir("/tmp");
  if (chroot("/tmp") != 0) {
    perror("chroot /tmp");
  }
  seteuid(1077);
}

void chroot_safe5(){
  if (chroot("/tmp") != 0) {
    perror("chroot /tmp");
  }
  chdir("/");
}

int main(void) {
  chroot_fail();

  chroot_safe1();
  chroot_safe2();
  chroot_safe3();
  chroot_safe4();
  chroot_safe5();
}
