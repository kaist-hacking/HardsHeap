#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SO_FILE=$DIR/FreeGuard/libfreeguard.so

if [ ! -e $SO_FILE ]; then
  pushd $DIR
  git clone https://github.com/UTSASRG/FreeGuard.git
  pushd FreeGuard
  git checkout bfdf6d9a
  patch < ../libfreeguard.patch
  make SSE2RNG=1
  popd
  popd
fi

HARDSHEAP_PRELOAD=$SO_FILE "$@"
