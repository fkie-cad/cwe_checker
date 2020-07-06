#!/bin/bash

tmp="$HOME/cwe_checker/test/unit/tmp/"

# create a tmp directory if not yet created
if [ ! -d $tmp ]; then
  mkdir -p $tmp;
fi


c_compiler=(gcc
            x86_64-w64-mingw32-gcc
            i686-w64-mingw32-gcc
            arm-linux-gnueabi-gcc
            aarch64-linux-gnu-gcc
            mips-linux-gnu-gcc
            mipsel-linux-gnu-gcc
            mips64-linux-gnuabi64-gcc
            mips64el-linux-gnuabi64-gcc
            powerpc-linux-gnu-gcc
            powerpc64-linux-gnu-gcc
            powerpc64le-linux-gnu-gcc
            clang)

cpp_compiler=(g++
              x86_64-w64-mingw32-g++
              i686-w64-mingw32-g++
              arm-linux-gnueabi-g++
              aarch64-linux-gnu-g++
              mips-linux-gnu-g++
              mipsel-linux-gnu-g++
              mips64-linux-gnuabi64-g++
              mips64el-linux-gnuabi64-g++
              powerpc-linux-gnu-g++
              powerpc64-linux-gnu-g++
              powerpc64le-linux-gnu-g++)

# In clang cross compilation there is no target for ppc 32 bit
targets=(x86_64-linux-gnuabi64
         arm-linux-gnueabi
         aarch64-linux-gnu
         mips-linux-gnu
         mipsel-linux-gnu
         mips64-linux-gnuabi64
         mips64el-linux-gnuabi64
         powerpc64-linux-gnu
         powerpc64le-linux-gnu)

x86_flag="-m32"

c_flag="-std=c11"

flags="-g -fno-stack-protector"

target_flag="-target"

function compile_clang () {
  for target in ${targets[@]}
  do
    build_name="$tmp$2"
    build_name+="_$(cut -d'-' -f1 <<<$target)_clang.out"
    $1 $flags $c_flag $target_flag $target $3 -o $build_name
  done
}

function compile_x86 () {
  build_name="$tmp$2"
  build_name+="_x86_gcc.out"
  gcc $x86_flag $flags $c_flag $1 -o $build_name
  build_name="$tmp$2"
  build_name+="_x86_clang.out"
  clang $x86_flag $flags $c_flag $1 -o $build_name
}


function compile_x86_for_cpp () {
  build_name="$tmp${2}_x86_g++.out"
  g++ $x86_flag $flags $1 -o $build_name
}


function compile_gcc () {
  build_name="$tmp$2"
  if [[ $1 == gcc ]]; then
    build_name+="_$1.out"
  else
    if [[ $1 == *w64* ]]; then
      build_name+="_${1%-*}_gcc.out"
    else
      build_name+="_${1%%-*}_gcc.out"
    fi
  fi
  $1 $flags $c_flag $3 -o $build_name
}


function compile_c () {
  file_name=$2
  c_file=$1
  for compiler in ${c_compiler[@]}
  do
    if [[ $compiler == clang ]]; then
      compile_clang "$compiler" "$file_name" "$c_file"
    else
      compile_gcc "$compiler" "$file_name" "$c_file"
    fi
  done

  compile_x86 "$c_file" "$file_name"
}


function compile_cpp () {
  for compiler in ${cpp_compiler[@]}
  do
    build_name="$tmp$2"
    if [[ $compiler == g++ ]]; then
      build_name+="_$compiler.out"
    else
      if [[ $compiler == *w64* ]]; then
        build_name+="_${compiler%-*}_g++.out"
      else
        build_name+="_${compiler%%-*}_g++.out"
      fi
    fi
    $compiler $flags $1 -o $build_name
  done
  compile_x86_for_cpp "$1" "$2"
}


function main () {
  test_file="$1"
  echo "Compiling test file $test_file"
  file_name="${test_file%.*}"
  file_name="${file_name##*/}"

  if [[ $test_file == *.c ]]; then
    compile_c "$test_file" "$file_name"
  elif [[ $test_file == *.cpp ]]; then
    compile_cpp "$test_file" "$file_name"
  fi
}

main "$@"
