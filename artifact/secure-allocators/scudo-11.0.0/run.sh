#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SO_FILE=$DIR/clang+llvm-11.0.0-x86_64-linux-gnu-ubuntu-20.04/lib/clang/11.0.0/lib/linux/libclang_rt.scudo-x86_64.so

if [ ! -e $SO_FILE ]; then
  pushd $DIR
  wget https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.0/clang+llvm-11.0.0-x86_64-linux-gnu-ubuntu-20.04.tar.xz
  tar -xvf clang+llvm-11.0.0-x86_64-linux-gnu-ubuntu-20.04.tar.xz
  popd
fi

HARDSHEAP_PRELOAD=$SO_FILE "$@"
