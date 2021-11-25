#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SO_FILE=$DIR/Guarder/libguarder.so

if [ ! -e $SO_FILE ]; then
  pushd $DIR
  git clone https://github.com/UTSASRG/Guarder.git
  pushd Guarder
  git checkout 9e85978a
  patch < ../libguarder.patch
  make
  popd
  popd
fi

HARDSHEAP_PRELOAD=$SO_FILE "$@"
