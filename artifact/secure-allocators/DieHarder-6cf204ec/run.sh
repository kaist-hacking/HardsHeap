#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SO_FILE=$DIR/DieHard/src/dieharder.so
if [ ! -e $SO_FILE ]; then
  pushd $DIR
  git clone --recursive https://github.com/emeryberger/DieHard
  pushd DieHard/src
  git checkout 6cf204ec
  TARGET=dieharder make linux-gcc-x86-64
  popd
  popd
fi

HARDSHEAP_PRELOAD=$SO_FILE "$@"
