#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SO_FILE=$DIR/isoalloc/build/libisoalloc.so

if [ ! -e $SO_FILE ]; then
  pushd $DIR
  git clone https://github.com/struct/isoalloc.git
  pushd isoalloc
  git checkout a683f42
  make library
  popd
  popd
fi

HARDSHEAP_PRELOAD=$SO_FILE "$@"
