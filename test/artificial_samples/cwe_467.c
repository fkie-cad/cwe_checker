/* taken from https://cwe.mitre.org/data/definitions/467.html and slightly modified */
/* Ignore CWE-259 (hard-coded password) and CWE-309 (use of password system for authentication) for this example. */

#include <stdlib.h>
#include <stdio.h>

#define AUTH_SUCCESS 1
#define AUTH_FAIL 0

char *username = "admin";
char *pass = "password";

int AuthenticateUser(char *inUser, char *inPass) {
  printf("Sizeof username = %d\n", sizeof(username));
  printf("Sizeof pass = %d\n", sizeof(pass));

  if (strncmp(username, inUser, sizeof(username))) {
    printf("Auth failure of username using sizeof\n");
    return AUTH_FAIL;
  }
  /* Because of CWE-467, the sizeof returns 4 on many platforms and architectures. */

  if (! strncmp(pass, inPass, sizeof(pass))) {
    printf("Auth success of password using sizeof\n");
    return AUTH_SUCCESS;
  }
  else {
    printf("Auth fail of password using sizeof\n");
    return AUTH_FAIL;
  }
}

int main (int argc, char **argv) {
  int authResult;

  if (argc < 3) {
    printf("Usage: Provide a username and password\n");
    exit(1);
  }
  authResult = AuthenticateUser(argv[1], argv[2]);
  if (authResult != AUTH_SUCCESS) {
    printf("Authentication failed\n");
    exit(1);
  }
  else {
    printf("Authenticated\n");
    exit(0);
  }
}
