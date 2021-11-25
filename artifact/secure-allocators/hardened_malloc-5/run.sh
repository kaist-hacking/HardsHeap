#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SO_FILE=$DIR/hardened_malloc/libhardened_malloc.so

if [ ! -e $SO_FILE ]; then
  pushd $DIR
  git clone https://github.com/GrapheneOS/hardened_malloc.git
  pushd hardened_malloc
  git checkout 5c8b686
  make libhardened_malloc.so
  popd
  popd
fi

HARDSHEAP_PRELOAD=$SO_FILE "$@"
