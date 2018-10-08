// taken from https://exploit-exercises.com/nebula/level01/

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

void vulnerable_sub(){
  gid_t gid;
  uid_t uid;
  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  system("/usr/bin/env echo and now what?");
}

int main(int argc, char **argv, char **envp)
{
  vulnerable_sub();
}
