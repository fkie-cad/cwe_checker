#include <iostream>
using namespace std;

void throw_exception(int i) {
  cout<< " Throwing exception "<< i << endl;
  throw i;
}

int main() {
  // Throw and directly catch an exception
  try {
    throw 'e';
  }
  catch(char c)
  {
    cout<<"Exception "<< c <<" successfuly catched." << endl;
  }
  // Throw in a subfunction and catch it.
  try {
    throw_exception(20);
  }
  catch(int e)
  {
    cout<<"Exception "<< e <<" successfuly catched." << endl;
  };
  // Now throw without catching:
  throw_exception(42);
}
