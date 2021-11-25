#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SO_FILE=$DIR/mimalloc/out/secure/libmimalloc-secure.so

if [ ! -e $SO_FILE ]; then
  pushd $DIR
  git clone https://github.com/microsoft/mimalloc.git

  pushd mimalloc

  git checkout v1.7.0
  mkdir -p out/secure
  cd out/secure
  cmake -DMI_SECURE=ON ../..
  make

  popd
  popd
fi

HARDSHEAP_PRELOAD=$SO_FILE "$@"
