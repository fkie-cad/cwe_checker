#include <iostream>
using namespace std;

void throw_exception(int i) {
  cout<< " Throwing exception "<< i << endl;
  throw i;
}

void do_catch(int i) {
  try {
    throw i;
  }
  catch(int error) {
    cout<<"Exception " << i << "successfully catched."<<endl;
  }
}

void maybe_catch(int i) {
  if(i<42) {
    try {
      throw_exception(i);
    }
    catch(int errror) {
      // Yay, catched.
      cout<<"Exception " << i << " successfully catched."<<endl;
    }
  }
  else {
    // We don't catch anything here.
    throw_exception(i);
  }
}

int main() {
  cout<<"Enter a number." <<endl;
  int i;
  cin >> i;
  maybe_catch(i);
  do_catch(i);
  // For good measure, just throw an exception here.
  throw (i+20);
}
