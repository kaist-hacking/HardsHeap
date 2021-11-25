#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SO_FILE=$DIR/MarkUs-sp2020/bdwgc-markus/.libs/libgc.so
SO_FILE2=$DIR/MarkUs-sp2020/bdwgc-markus/.libs/libgccpp.so

if [ ! -e $SO_FILE ] || [ ! -e $SO_FILE2 ] ; then
  pushd $DIR
  git clone https://github.com/SamAinsworth/MarkUs-sp2020.git
  pushd MarkUs-sp2020
  git checkout 4c75ffd5
  ./setup.sh
  popd
  popd
fi

HARDSHEAP_PRELOAD="$SO_FILE:$SO_FILE2" "$@"
