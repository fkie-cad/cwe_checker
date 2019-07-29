#include <stdlib.h>

void if_statement(){
  void* bla = malloc(89);
  int a = 2;
  if (a < 4){
    a = 33;
  }
  free(bla);
}

void for_loop(){
  void* bla = malloc(89);
  int a = 34;
  for(int i = 0;i < 100; i++){
    a += i;
  }
  free(bla);
}

void nested_for_loop(){
  void* bla = malloc(89);
  int a = 34;
  for(int i = 0; i < 100; i++){
    for(int j = 0; j < 200; j++){
      a += i + j;
    }
  }
  free(bla);
}

int main(){
  if_statement();
  for_loop();
  nested_for_loop();
}
