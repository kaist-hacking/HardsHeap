#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SO_FILE=$DIR/mallocng-draft/libmallocng.so

if [ ! -e $SO_FILE ]; then
  pushd $DIR
  git clone https://github.com/richfelker/mallocng-draft
  pushd mallocng-draft
  git checkout 2ed5881
  make libmallocng.so
  popd
  popd
fi

HARDSHEAP_PRELOAD=$SO_FILE "$@"
