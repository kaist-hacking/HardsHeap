#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SO_FILE=$DIR/ffmalloc/libffmallocnpst.so
if [ ! -e $SO_FILE ]; then
  pushd $DIR
  git clone https://github.com/bwickman97/ffmalloc.git
  pushd ffmalloc
  git checkout 9e1e5825
  make
  popd
  popd
fi

HARDSHEAP_PRELOAD=$SO_FILE "$@"
