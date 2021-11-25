#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SO_FILE=$DIR/SlimGuard/build/src/libSlimGuard.so

if [ ! -e $SO_FILE ]; then
  pushd $DIR
  git clone https://github.com/ssrg-vt/SlimGuard.git
  pushd SlimGuard
  git checkout 237d842a

  patch -p0 < ../libSlimGuard.patch

  mkdir build
  pushd build
  cmake ..
  make SlimGuard
  popd

  popd
  popd
fi

HARDSHEAP_PRELOAD=$SO_FILE "$@"
