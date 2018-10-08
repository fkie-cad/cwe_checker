#include <stdlib.h>

void func1(){
  void* data = malloc(20);
  if (data == NULL){
    exit(42);
  }
  free(data);
}

void func2(){
 void* data = malloc(20);
 free(data);
} 

void main() {

  func1();
  func2();
  
}
