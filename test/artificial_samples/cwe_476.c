#include <stdlib.h>

void func1(){
  void* data = malloc(20000);
  if (data == NULL){
    exit(42);
  }
  free(data);
}

void func2(){
 int* data = malloc(200000);
 printf("%i", data[0]);
 free(data);
}

void main() {

  func1();
  func2();

}
